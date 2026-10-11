<?php

declare(strict_types=1);

namespace CoyoteCert;

use CoyoteCert\Challenge\Dns\AbstractDns01Handler;
use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\Dns01ValidationData;
use CoyoteCert\DTO\Http01ValidationData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\DTO\RenewalWindow;
use CoyoteCert\DTO\TlsAlpn01ValidationData;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Enums\RevocationReason;
use CoyoteCert\Exceptions\AccountNotFoundException;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Http\Client as HttpClient;
use CoyoteCert\Http\Psr18Adapter;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Storage\StorageInterface;
use CoyoteCert\Storage\StoredCertificate;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\CaaChecker;
use CoyoteCert\Support\OpenSsl;
use DateTimeImmutable;
use Psr\Log\LoggerInterface;

class CoyoteCert
{
    private ?StorageInterface          $storage    = null;
    private ?LoggerInterface           $logger     = null;
    private ?HttpClientInterface       $httpClient = null;
    private string                     $email      = '';
    private string                     $profile    = '';
    /** @var string[] */
    private array                      $domains          = [];
    private ?ChallengeHandlerInterface $challengeHandler = null;
    private KeyType                    $certKeyType      = KeyType::EC_P256;
    private KeyType                    $accountKeyType   = KeyType::EC_P256;
    private bool                       $localTest        = true;
    private bool                       $skipCaaCheck     = false;
    private string                     $preferredChain   = '';
    private int                        $pollAttempts     = 10;
    /** @var callable[] */
    private array $onIssuedCallbacks = [];
    /** @var callable[] */
    private array $onRenewedCallbacks = [];

    private function __construct(private readonly AcmeProviderInterface $provider) {}

    // ── Builder ───────────────────────────────────────────────────────────────

    public static function with(AcmeProviderInterface $provider): self
    {
        return new self($provider);
    }

    public function email(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function profile(string $profile): self
    {
        $this->profile = $profile;

        return $this;
    }

    public function storage(StorageInterface $storage): self
    {
        $this->storage = $storage;

        return $this;
    }

    public function logger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * Use a PSR-18 HTTP client instead of the built-in curl client.
     * $requestFactory and $streamFactory are optional when the client also implements those interfaces.
     */
    public function httpClient(
        \Psr\Http\Client\ClientInterface $client,
        ?\Psr\Http\Message\RequestFactoryInterface $requestFactory = null,
        ?\Psr\Http\Message\StreamFactoryInterface $streamFactory = null,
    ): self {
        $this->httpClient = new Psr18Adapter($client, $requestFactory, $streamFactory);

        return $this;
    }

    /** @param string|string[] $identifiers Domain names and/or IP addresses (RFC 8738). */
    public function identifiers(array|string $identifiers): self
    {
        // DNS names are case-insensitive; lower-casing keeps storage keys stable
        $list = array_map(strtolower(...), is_array($identifiers) ? array_values($identifiers) : [$identifiers]);

        foreach ($list as $domain) {
            if (!self::isValidDomain($domain) && !filter_var($domain, FILTER_VALIDATE_IP)) {
                throw new AcmeException(sprintf('Invalid domain name or IP address: "%s".', $domain));
            }
        }

        $this->domains = $list;

        return $this;
    }

    public function challenge(ChallengeHandlerInterface $handler): self
    {
        $this->challengeHandler = $handler;

        return $this;
    }

    public function keyType(KeyType $type): self
    {
        $this->certKeyType = $type;

        return $this;
    }

    public function accountKeyType(KeyType $type): self
    {
        $this->accountKeyType = $type;

        return $this;
    }

    /** Maximum number of polling attempts when waiting for challenges to pass (default: 10). */
    public function pollAttempts(int $attempts): self
    {
        $this->pollAttempts = $attempts;

        return $this;
    }

    /** Disable the pre-flight self-check before notifying the CA. */
    public function skipLocalTest(): self
    {
        $this->localTest = false;

        return $this;
    }

    /** Skip the CAA DNS pre-check (useful when DNS is internal or not reachable). */
    public function skipCaaCheck(): self
    {
        $this->skipCaaCheck = true;

        return $this;
    }

    /**
     * Prefer the chain whose topmost certificate was issued by $issuer, the root's Common Name
     * (case-insensitive, like certbot's --preferred-chain). Falls back to the CA's default chain.
     */
    public function preferredChain(string $issuer): self
    {
        $this->preferredChain = $issuer;

        return $this;
    }

    /** Callback invoked after every successful issuance. Receives the StoredCertificate. */
    public function onIssued(callable $callback): self
    {
        $this->onIssuedCallbacks[] = $callback;

        return $this;
    }

    /**
     * Callback invoked when an existing certificate is replaced.
     * Fires after onIssued callbacks. Receives the new StoredCertificate.
     */
    public function onRenewed(callable $callback): self
    {
        $this->onRenewedCallbacks[] = $callback;

        return $this;
    }

    /** No-op when a custom PSR-18 client is configured. */
    public function withHttpTimeout(int $seconds): self
    {
        if ($this->httpClient instanceof HttpClient) {
            $this->httpClient->setTimeout($seconds);
        } elseif ($this->httpClient === null) {
            $this->httpClient = new HttpClient(timeout: $seconds);
        }

        return $this;
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /**
     * Whether the certificate is missing, expired, no longer covers the configured identifiers,
     * or is due for renewal. The CA's ARI window decides when available. Otherwise renewal is due
     * once a third of the lifetime remains (30 days for a 90-day certificate, 2 for a 6-day one),
     * or within $daysBeforeExpiry days when given.
     */
    public function needsRenewal(?int $daysBeforeExpiry = null): bool
    {
        if ($this->storage === null || empty($this->domains)) {
            return true;
        }

        $cert = $this->storage->getCertificate($this->domains[0], $this->certKeyType);

        if ($cert === null || $cert->isExpired() || !$this->coversIdentifiers($cert)) {
            return true;
        }

        $window = $this->ariWindow($cert);

        if ($window !== null) {
            return $window->isOpen();
        }

        if ($daysBeforeExpiry !== null) {
            return $cert->remainingDays() <= $daysBeforeExpiry;
        }

        $lifetime = $cert->expiresAt->getTimestamp() - $cert->issuedAt->getTimestamp();

        return $cert->expiresAt->getTimestamp() - time() <= intdiv($lifetime, 3);
    }

    // ── Terminal actions ──────────────────────────────────────────────────────

    public function issue(): StoredCertificate
    {
        $this->validate();

        $challengeHandler = $this->challengeHandler ?? throw new AcmeException('No challenge handler configured.');

        $api = new Api(
            provider: $this->provider,
            // Without storage the account key only lives for this call, so each issue() registers a new account
            storage: $this->storage ?? new InMemoryStorage(),
            logger: $this->logger,
            httpClient: $this->httpClient,
            accountKeyType: $this->accountKeyType,
        );

        if (!$this->skipCaaCheck) {
            $this->checkCaa($api);
        }

        $account = $this->getOrCreateAccount($api);

        $replacesId   = '';
        $existingCert = $this->storage?->getCertificate($this->domains[0], $this->certKeyType);
        $sameProvider = $existingCert?->providerSlug === $this->provider->getSlug();
        if ($existingCert !== null && $sameProvider) {
            try {
                $replacesId = $api->renewalInfo()->certId($existingCert->certificate);
            } catch (\Throwable) {
                // certId failure is non-critical; proceed without replaces
            }
        }

        $order = $api->order()->new($account, $this->domains, $this->profile, $replacesId);

        $this->deployAndValidate($api, $order, $account, $challengeHandler);

        // Refresh order: status transitions pending → ready after all challenges pass
        $order = $api->order()->refresh($order);

        $stored = $this->fetchAndStoreCertificate($api, $order);
        $this->fireIssuedCallbacks($stored, isRenewal: $existingCert !== null);

        return $stored;
    }

    /** Issue only when needsRenewal() says so, otherwise return the stored certificate. */
    public function issueOrRenew(?int $daysBeforeExpiry = null): StoredCertificate
    {
        if (!$this->needsRenewal($daysBeforeExpiry)) {
            // needsRenewal() returns false only when storage is set and a cert exists
            return $this->storage?->getCertificate($this->domains[0], $this->certKeyType)
                ?? throw new AcmeException('Certificate unexpectedly missing from storage.');
        }

        return $this->issue();
    }

    /** Requires storage: the account key is used to sign the revocation request. */
    public function revoke(StoredCertificate $cert, RevocationReason $reason = RevocationReason::Unspecified): void
    {
        if ($this->storage === null) {
            throw new AcmeException(
                'No storage configured. Call ->storage() before revoking.',
            );
        }

        $api = new Api(
            provider: $this->provider,
            storage: $this->storage,
            logger: $this->logger,
            httpClient: $this->httpClient,
            accountKeyType: $this->accountKeyType,
        );

        $api->certificate()->revoke($cert->certificate, $reason);
    }

    // ── Private issue() helpers ───────────────────────────────────────────────

    /**
     * The CA's own caaIdentities complement the provider's list: a CAA record naming any of
     * them authorises the CA. A provider returning no identifiers opts out of the check.
     */
    private function checkCaa(Api $api): void
    {
        $identities = $this->provider->getCaaIdentifiers();

        if ($identities === []) {
            return;
        }

        $identities = array_values(array_unique([...$identities, ...Arr::strings($api->directory()->meta(), 'caaIdentities')]));
        $domains    = array_values(array_filter(
            $this->domains,
            static fn(string $id): bool => !filter_var($id, FILTER_VALIDATE_IP),
        ));

        if ($domains !== []) {
            (new CaaChecker())->check($domains, $identities);
        }
    }

    private function getOrCreateAccount(Api $api): AccountData
    {
        if (!$api->account()->exists()) {
            return $api->account()->create($this->email);
        }

        try {
            return $api->account()->get();
        } catch (AccountNotFoundException) {
            // The stored key was never registered (e.g. an earlier signup failed): register it now
            $api->logger('info', 'Stored account key is not registered with the CA, creating the account.');

            return $api->account()->create($this->email);
        }
    }

    private function deployAndValidate(
        Api $api,
        OrderData $order,
        AccountData $account,
        ChallengeHandlerInterface $challengeHandler,
    ): void {
        if ($this->logger !== null && $challengeHandler instanceof AbstractDns01Handler) {
            $challengeHandler = $challengeHandler->withLogger($this->logger);
        }

        $challenges    = $api->domainValidation()->status($order);
        $challengeType = $this->detectChallengeType();
        // Authorizations the CA reused from an earlier order are already valid: nothing to deploy
        $validationData = $api->domainValidation()->getValidationData(
            array_filter($challenges, static fn($authz): bool => !$authz->isValid()),
            $challengeType,
        );

        // Write every TXT record before waiting on DNS. A wildcard and its base name
        // share one _acme-challenge record set, and publishing the second value only
        // after the first has propagated leaves a partial set live long enough for the
        // CA's resolvers to cache it and reject the sibling challenge.
        $dnsHandler = $challengeHandler instanceof AbstractDns01Handler ? $challengeHandler : null;
        $deployed   = [];

        // Everything from the first deploy() on runs inside the try, so a failed deploy,
        // propagation wait, local self-test or challenge submission still cleans up.
        try {
            $dnsHandler?->beginDeployBatch();

            foreach ($validationData as $item) {
                [$token, $keyAuth] = $this->extractTokenAndKeyAuth($item);
                $api->logger('info', sprintf('Deploy %s challenge for %s', $challengeType->value, $item->identifier));
                // Tracked before the call so a deploy that fails partway is cleaned up too
                $deployed[] = $item;
                $challengeHandler->deploy($item->identifier, $token, $keyAuth);
            }

            $dnsHandler?->awaitDeployedRecords();

            foreach ($challenges as $domainValidation) {
                if ($domainValidation->isValid()) {
                    continue;
                }
                $api->domainValidation()->start($account, $domainValidation, $challengeType, $this->localTest);
            }

            $allPassed = $api->domainValidation()->allChallengesPassed($order, $this->pollAttempts, $challengeType);
        } finally {
            foreach ($deployed as $item) {
                [$token] = $this->extractTokenAndKeyAuth($item);

                // A failed cleanup must neither mask the validation result nor skip the remaining items
                try {
                    $challengeHandler->cleanup($item->identifier, $token);
                } catch (\Throwable $e) {
                    $api->logger('warning', sprintf(
                        'Cleanup of %s challenge for %s failed: %s',
                        $challengeType->value,
                        $item->identifier,
                        $e->getMessage(),
                    ));
                }
            }
        }

        if (!$allPassed) {
            throw new AcmeException(
                'Domain validation failed: one or more challenges did not pass.',
            );
        }
    }

    private function fetchAndStoreCertificate(Api $api, OrderData $order): StoredCertificate
    {
        $certKey    = OpenSsl::generateKey($this->certKeyType);
        $certKeyPem = OpenSsl::openSslKeyToString($certKey);
        $csr        = OpenSsl::generateCsr($this->domains, $certKey);

        $api->logger('info', 'Submitting CSR and finalizing order.');
        $api->order()->finalize($order, $csr);

        $order  = $api->order()->waitUntilValid($order);
        $bundle = $api->certificate()->getBundle($order, $this->preferredChain ?: null);

        $parsed = openssl_x509_parse($bundle->certificate);

        if ($parsed === false || !isset($parsed['validTo_time_t'])) {
            throw new AcmeException('The CA returned a certificate that cannot be parsed.');
        }

        $expiresAt = (new DateTimeImmutable())->setTimestamp((int) $parsed['validTo_time_t']);

        $api->logger('info', sprintf('Certificate issued, expires %s.', $expiresAt->format('Y-m-d')));

        $stored = new StoredCertificate(
            certificate: $bundle->certificate,
            privateKey: $certKeyPem,
            fullchain: $bundle->fullchain,
            caBundle: $bundle->caBundle,
            issuedAt: new DateTimeImmutable(),
            expiresAt: $expiresAt,
            domains: $this->domains,
            keyType: $this->certKeyType,
            providerSlug: $this->provider->getSlug(),
        );

        if ($this->storage !== null) {
            $this->storage->saveCertificate($this->domains[0], $stored);
            $api->logger('info', 'Certificate saved to storage.');
        }

        return $stored;
    }

    private function fireIssuedCallbacks(StoredCertificate $cert, bool $isRenewal): void
    {
        foreach ($this->onIssuedCallbacks as $cb) {
            $cb($cert);
        }

        if ($isRenewal) {
            foreach ($this->onRenewedCallbacks as $cb) {
                $cb($cert);
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private function coversIdentifiers(StoredCertificate $cert): bool
    {
        try {
            return $cert->isValidForDomains($this->domains);
        } catch (CryptoException) {
            return false; // an unreadable stored certificate is replaced
        }
    }

    private function ariWindow(StoredCertificate $cert): ?RenewalWindow
    {
        try {
            return (new Api(provider: $this->provider, logger: $this->logger, httpClient: $this->httpClient))
                ->renewalInfo()
                ->get($cert->certificate);
        } catch (\Throwable) {
            return null;
        }
    }

    private function validate(): void
    {
        if (empty($this->domains)) {
            throw new AcmeException(
                'No identifiers configured. Call ->identifiers() before issuing a certificate.',
            );
        }

        if ($this->challengeHandler === null) {
            throw new AcmeException(
                'No challenge handler configured. Call ->challenge() before issuing a certificate.',
            );
        }

        // Fail before any network round-trip when the handler can't validate the identifiers
        $this->detectChallengeType();
    }

    private function detectChallengeType(): AuthorizationChallengeEnum
    {
        // Wildcard identifiers can only be validated with dns-01 (RFC 8555 §7.1.3)
        if (array_filter($this->domains, static fn(string $id): bool => str_starts_with($id, '*.')) !== []) {
            return $this->challengeHandler?->supports(AuthorizationChallengeEnum::DNS)
                ? AuthorizationChallengeEnum::DNS
                : throw new AcmeException('Wildcard identifiers need a dns-01 challenge handler.');
        }

        foreach (AuthorizationChallengeEnum::cases() as $type) {
            if ($this->challengeHandler?->supports($type)) {
                return $type;
            }
        }

        throw new AcmeException(
            'The configured challenge handler does not support any known challenge type.',
        );
    }

    /** @return array{0: string, 1: string} */
    private function extractTokenAndKeyAuth(Http01ValidationData|Dns01ValidationData|TlsAlpn01ValidationData $item): array
    {
        if ($item instanceof Http01ValidationData) {
            return [$item->filename, $item->content];
        }

        if ($item instanceof TlsAlpn01ValidationData) {
            return [$item->token, $item->keyAuthorization];
        }

        return [$item->name, $item->value];
    }

    private static function isValidDomain(string $domain): bool
    {
        // Strip one leading wildcard label before validating the rest
        $check = str_starts_with($domain, '*.') ? substr($domain, 2) : $domain;

        return (bool) preg_match(
            '/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/',
            $check,
        );
    }
}
