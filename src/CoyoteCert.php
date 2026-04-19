<?php

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
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Client as HttpClient;
use CoyoteCert\Http\Psr18Adapter;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Storage\StorageInterface;
use CoyoteCert\Storage\StoredCertificate;
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
        $list = is_array($identifiers) ? array_values($identifiers) : [$identifiers];

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
     * Prefer a chain whose intermediates contain $issuer (case-insensitive substring match).
     * Falls back to the CA's default chain when no alternate chain matches.
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

    public function needsRenewal(int $daysBeforeExpiry = 30): bool
    {
        if ($this->storage === null || empty($this->domains)) {
            return true;
        }

        $cert = $this->storage->getCertificate($this->domains[0], $this->certKeyType);

        if ($cert === null) {
            return true;
        }

        $window = $this->ariWindow($cert);

        if ($window !== null) {
            return $window->isOpen();
        }

        return $cert->remainingDays() <= $daysBeforeExpiry;
    }

    // ── Terminal actions ──────────────────────────────────────────────────────

    public function issue(): StoredCertificate
    {
        $this->validate();

        if (!$this->skipCaaCheck) {
            $domainIdentifiers = array_values(array_filter(
                $this->domains,
                static fn(string $id): bool => !filter_var($id, FILTER_VALIDATE_IP),
            ));

            if (!empty($domainIdentifiers)) {
                (new CaaChecker())->check($domainIdentifiers, $this->provider->getCaaIdentifiers());
            }
        }

        $challengeHandler = $this->challengeHandler ?? throw new AcmeException('No challenge handler configured.');

        $api = new Api(
            provider: $this->provider,
            storage: $this->storage,
            logger: $this->logger,
            httpClient: $this->httpClient,
            accountKeyType: $this->accountKeyType,
        );

        $account = $this->getOrCreateAccount($api);

        $replacesId   = '';
        $existingCert = $this->storage?->getCertificate($this->domains[0], $this->certKeyType);
        $sameProvider = $existingCert?->providerSlug === $this->provider->getSlug();
        if ($existingCert !== null && $sameProvider && ($issuerPem = $this->extractIssuerPem($existingCert)) !== null) {
            try {
                $replacesId = $api->renewalInfo()->certId($existingCert->certificate, $issuerPem);
            } catch (\Throwable) {
                // certId failure is non-critical; proceed without replaces
            }
        }

        $order = $api->order()->new($account, $this->domains, $this->profile, $replacesId);

        $this->deployAndValidate($api, $order, $account, $challengeHandler);

        // Refresh order — status transitions pending → ready after all challenges pass
        $order = $api->order()->refresh($order);

        $stored = $this->fetchAndStoreCertificate($api, $order);
        $this->fireIssuedCallbacks($stored, isRenewal: $existingCert !== null);

        return $stored;
    }

    /** Issue only when the certificate is absent or expires within $daysBeforeExpiry days. */
    public function issueOrRenew(int $daysBeforeExpiry = 30): StoredCertificate
    {
        if (!$this->needsRenewal($daysBeforeExpiry)) {
            // needsRenewal() returns false only when storage is set and a cert exists
            return $this->storage?->getCertificate($this->domains[0], $this->certKeyType)
                ?? throw new AcmeException('Certificate unexpectedly missing from storage.');
        }

        return $this->issue();
    }

    /** Requires storage — the account key is used to sign the revocation request. */
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

        $api->certificate()->revoke($cert->certificate, $reason->value);
    }

    // ── Private issue() helpers ───────────────────────────────────────────────

    private function getOrCreateAccount(Api $api): AccountData
    {
        return $api->account()->exists()
            ? $api->account()->get()
            : $api->account()->create($this->email);
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

        $challenges     = $api->domainValidation()->status($order);
        $challengeType  = $this->detectChallengeType();
        $validationData = $api->domainValidation()->getValidationData($challenges, $challengeType);

        foreach ($validationData as $item) {
            [$token, $keyAuth] = $this->extractTokenAndKeyAuth($item);
            $api->logger('info', sprintf('Deploy %s challenge for %s', $challengeType->value, $item->identifier));
            $challengeHandler->deploy($item->identifier, $token, $keyAuth);
        }

        foreach ($challenges as $domainValidation) {
            if ($domainValidation->isValid()) {
                continue;
            }
            $api->domainValidation()->start($account, $domainValidation, $challengeType, $this->localTest);
        }

        $allPassed = $api->domainValidation()->allChallengesPassed($order, $this->pollAttempts);

        foreach ($validationData as $item) {
            [$token] = $this->extractTokenAndKeyAuth($item);
            $challengeHandler->cleanup($item->identifier, $token);
        }

        if (!$allPassed) {
            throw new AcmeException(
                'Domain validation failed — one or more challenges did not pass.',
            );
        }
    }

    private function fetchAndStoreCertificate(Api $api, OrderData $order): StoredCertificate
    {
        $certKey    = OpenSsl::generateKey($this->certKeyType);
        $certKeyPem = OpenSsl::openSslKeyToString($certKey);
        $csr        = OpenSsl::generateCsr($this->domains, $certKey);

        $api->order()->finalize($order, $csr);

        $order  = $api->order()->waitUntilValid($order);
        $bundle = $api->certificate()->getBundle($order, $this->preferredChain ?: null);

        $parsed    = openssl_x509_parse($bundle->certificate);
        $expiresAt = isset($parsed['validTo_time_t'])
            ? (new DateTimeImmutable())->setTimestamp((int) $parsed['validTo_time_t'])
            : new DateTimeImmutable('+90 days');

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

    private function ariWindow(StoredCertificate $cert): ?RenewalWindow
    {
        $issuerPem = $this->extractIssuerPem($cert);

        if ($issuerPem === null) {
            return null;
        }

        try {
            return (new Api(provider: $this->provider, logger: $this->logger, httpClient: $this->httpClient))
                ->renewalInfo()
                ->get($cert->certificate, $issuerPem);
        } catch (\Throwable) {
            return null;
        }
    }

    private function extractIssuerPem(StoredCertificate $cert): ?string
    {
        if (empty($cert->caBundle)) {
            return null;
        }

        if (!preg_match('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~', $cert->caBundle, $m)) {
            return null;
        }

        return $m[1];
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
    }

    private function detectChallengeType(): AuthorizationChallengeEnum
    {
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
