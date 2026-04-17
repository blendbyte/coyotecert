<?php

namespace CoyoteCert;

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

/**
 * High-level fluent entry point for certificate issuance and renewal.
 *
 * Usage:
 *
 *   $cert = CoyoteCert::with(new LetsEncrypt())
 *       ->storage(new FilesystemStorage('/var/certs'))
 *       ->identifiers(['example.com', 'www.example.com'])
 *       ->challenge(new Http01Handler('/var/www/html'))
 *       ->issue();
 *
 * Or to issue only when the certificate is close to expiry:
 *
 *   $cert = CoyoteCert::with(new LetsEncrypt())
 *       ->storage(new FilesystemStorage('/var/certs'))
 *       ->identifiers('example.com')
 *       ->challenge(new Http01Handler('/var/www/html'))
 *       ->issueOrRenew();
 */
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

    /**
     * Request a specific ACME profile (e.g. 'shortlived', 'classic').
     * Silently ignored for CAs that don't support profiles.
     */
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
     *
     * $requestFactory and $streamFactory are optional when the PSR-18 client
     * also implements those interfaces (e.g. Symfony's Psr18Client).
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

    /**
     * Set the key type used for the domain certificate (default: EC_P256).
     */
    public function keyType(KeyType $type): self
    {
        $this->certKeyType = $type;

        return $this;
    }

    /**
     * Set the key type used for the ACME account key (default: EC_P256).
     */
    public function accountKeyType(KeyType $type): self
    {
        $this->accountKeyType = $type;

        return $this;
    }

    /**
     * Disable the pre-flight HTTP/DNS self-check that runs before notifying the CA.
     * Useful when the server is internal or challenge files are deployed elsewhere.
     */
    public function skipLocalTest(): self
    {
        $this->localTest = false;

        return $this;
    }

    /**
     * Skip the CAA DNS pre-check before submitting the order to the CA.
     * Useful when DNS is internal or the CAA records are managed outside your control.
     */
    public function skipCaaCheck(): self
    {
        $this->skipCaaCheck = true;

        return $this;
    }

    /**
     * Prefer a specific certificate chain by matching the issuer Common Name or
     * Organisation of the intermediate certificates (RFC 8555 §7.4.2).
     *
     * When the CA offers alternate chains via Link: rel="alternate" headers, the
     * first chain whose intermediates contain $issuer (case-insensitive substring)
     * is returned. Falls back to the default chain when no match is found.
     *
     * Example: ->preferredChain('ISRG Root X1')
     */
    public function preferredChain(string $issuer): self
    {
        $this->preferredChain = $issuer;

        return $this;
    }

    /**
     * Register a callback invoked after every successful certificate issuance.
     * The callback receives the issued StoredCertificate as its sole argument.
     * Multiple callbacks may be registered; they run in registration order.
     */
    public function onIssued(callable $callback): self
    {
        $this->onIssuedCallbacks[] = $callback;

        return $this;
    }

    /**
     * Register a callback invoked after a certificate is renewed (i.e. an existing
     * certificate was replaced). Fires in addition to onIssued callbacks.
     * The callback receives the new StoredCertificate as its sole argument.
     * Multiple callbacks may be registered; they run in registration order.
     */
    public function onRenewed(callable $callback): self
    {
        $this->onRenewedCallbacks[] = $callback;

        return $this;
    }

    /**
     * Set the HTTP timeout in seconds for the built-in curl client.
     * No-op when a custom PSR-18 client is configured.
     */
    public function withHttpTimeout(int $seconds): static
    {
        if ($this->httpClient instanceof HttpClient) {
            $this->httpClient->setTimeout($seconds);
        } elseif ($this->httpClient === null) {
            // Client is lazily created; store for later application.
            // We create a Client now with the desired timeout so it's ready.
            $client           = new HttpClient(timeout: $seconds);
            $this->httpClient = $client;
        }

        return $this;
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /**
     * Returns true when no valid certificate is stored or it expires within $daysBeforeExpiry days.
     */
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

    /**
     * Issue a new certificate unconditionally.
     */
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

        $challengeHandler = $this->challengeHandler;

        if ($challengeHandler === null) {
            throw new AcmeException('No challenge handler configured.');
        }

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
        if ($existingCert !== null && ($issuerPem = $this->extractIssuerPem($existingCert)) !== null) {
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
        $challenges     = $api->domainValidation()->status($order);
        $challengeType  = $this->detectChallengeType();
        $validationData = $api->domainValidation()->getValidationData($challenges, $challengeType);

        foreach ($validationData as $item) {
            [$token, $keyAuth] = $this->extractTokenAndKeyAuth($item);
            $challengeHandler->deploy($item->identifier, $token, $keyAuth);
        }

        foreach ($challenges as $domainValidation) {
            $api->domainValidation()->start($account, $domainValidation, $challengeType, $this->localTest);
        }

        $allPassed = $api->domainValidation()->allChallengesPassed($order);

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

    private function fetchAndStoreCertificate(
        Api $api,
        OrderData $order,
    ): StoredCertificate {
        $certKey    = OpenSsl::generateKey($this->certKeyType);
        $certKeyPem = OpenSsl::openSslKeyToString($certKey);
        $csr        = OpenSsl::generateCsr($this->domains, $certKey);

        if (!$api->order()->finalize($order, $csr)) {
            throw new AcmeException('Order finalization failed.');
        }

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

    /**
     * Alias for issue() — forces a fresh certificate regardless of expiry.
     */
    public function renew(): StoredCertificate
    {
        return $this->issue();
    }

    /**
     * Revoke a previously issued certificate.
     *
     * Requires storage to be configured (the account key is used to sign the request).
     */
    public function revoke(StoredCertificate $cert, RevocationReason $reason = RevocationReason::Unspecified): bool
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

        return $api->certificate()->revoke($cert->certificate, $reason->value);
    }

    /**
     * Issue only when the certificate is absent or expires within $daysBeforeExpiry days.
     * Returns the existing certificate if it is still valid.
     */
    public function issueOrRenew(int $daysBeforeExpiry = 30): StoredCertificate
    {
        if (!$this->needsRenewal($daysBeforeExpiry)) {
            // needsRenewal() returns false only when storage is set and the cert exists.
            if ($this->storage === null) {
                throw new AcmeException('Certificate unexpectedly missing from storage.');
            }

            return $this->storage->getCertificate($this->domains[0], $this->certKeyType)
                ?? throw new AcmeException('Certificate unexpectedly missing from storage.');
        }

        return $this->issue();
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

    private static function isValidDomain(string $domain): bool
    {
        // Strip one leading wildcard label before validating the rest.
        $check = str_starts_with($domain, '*.') ? substr($domain, 2) : $domain;

        // Each label: 1–63 chars, alphanumeric + hyphens, no leading/trailing hyphen.
        // At least two labels required (bare TLDs are not valid identifiers for ACME).
        return (bool) preg_match(
            '/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/',
            $check,
        );
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
        if ($this->challengeHandler === null) {
            throw new AcmeException(
                'No challenge handler configured. Call ->challenge() before issuing a certificate.',
            );
        }

        foreach (AuthorizationChallengeEnum::cases() as $type) {
            if ($this->challengeHandler->supports($type)) {
                return $type;
            }
        }

        throw new AcmeException(
            'The configured challenge handler does not support any known challenge type.',
        );
    }

    /**
     * Returns [token, keyAuthorization] from a typed validation DTO.
     *
     * @param Http01ValidationData|Dns01ValidationData|TlsAlpn01ValidationData $item
     * @return array{0: string, 1: string}
     */
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
}
