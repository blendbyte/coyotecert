<?php

namespace CoyoteCert;

use DateTimeImmutable;
use Psr\Log\LoggerInterface;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\DTO\RenewalWindow;
use CoyoteCert\Exceptions\LetsEncryptClientException;
use CoyoteCert\Http\Psr18Adapter;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Storage\StoredCertificate;
use CoyoteCert\Storage\StorageInterface;
use CoyoteCert\Support\OpenSsl;

/**
 * High-level fluent entry point for certificate issuance and renewal.
 *
 * Usage:
 *
 *   $cert = CoyoteCert::with(new LetsEncrypt())
 *       ->storage(new FilesystemStorage('/var/certs'))
 *       ->domains(['example.com', 'www.example.com'])
 *       ->challenge(new Http01Handler('/var/www/html'))
 *       ->issue();
 *
 * Or to issue only when the certificate is close to expiry:
 *
 *   $cert = CoyoteCert::with(new LetsEncrypt())
 *       ->storage(new FilesystemStorage('/var/certs'))
 *       ->domains('example.com')
 *       ->challenge(new Http01Handler('/var/www/html'))
 *       ->issueOrRenew();
 */
class CoyoteCert
{
    private ?StorageInterface          $storage          = null;
    private ?LoggerInterface           $logger           = null;
    private ?HttpClientInterface       $httpClient       = null;
    private string                     $email            = '';
    private string                     $profile          = '';
    private array                      $domains          = [];
    private ?ChallengeHandlerInterface $challengeHandler = null;
    private KeyType                    $certKeyType      = KeyType::EC_P256;
    private KeyType                    $accountKeyType   = KeyType::RSA_2048;
    private bool                       $localTest        = true;

    private function __construct(private readonly AcmeProviderInterface $provider)
    {
    }

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

    /** @param string|string[] $domains */
    public function domains(array|string $domains): self
    {
        $this->domains = is_array($domains) ? array_values($domains) : [$domains];

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
     * Set the key type used for the ACME account key (default: RSA_2048).
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

    // ── Queries ───────────────────────────────────────────────────────────────

    /**
     * Returns true when no valid certificate is stored or it expires within $daysBeforeExpiry days.
     */
    public function needsRenewal(int $daysBeforeExpiry = 30): bool
    {
        if ($this->storage === null || empty($this->domains)) {
            return true;
        }

        $cert = $this->storage->getCertificate($this->domains[0]);

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

        $api = new Api(
            provider:       $this->provider,
            storage:        $this->storage,
            logger:         $this->logger,
            httpClient:     $this->httpClient,
            accountKeyType: $this->accountKeyType,
        );

        // ── 1. Get or create ACME account ──────────────────────────────────
        $account = $api->account()->exists()
            ? $api->account()->get()
            : $api->account()->create($this->email);

        // ── 2. Create order ────────────────────────────────────────────────
        $order = $api->order()->new($account, $this->domains, $this->profile);

        // ── 3. Fetch authorization challenges ──────────────────────────────
        $challenges = $api->domainValidation()->status($order);

        // ── 4. Determine challenge type from the registered handler ────────
        $challengeType = $this->detectChallengeType();

        // ── 5. Compute validation data (token + key authorization) ─────────
        $validationData = $api->domainValidation()->getValidationData($challenges, $challengeType);

        // ── 6. Deploy challenge files/records for every domain ─────────────
        foreach ($validationData as $item) {
            [$token, $keyAuth] = $this->extractTokenAndKeyAuth($item, $challengeType);
            $this->challengeHandler->deploy($item['identifier'], $token, $keyAuth);
        }

        // ── 7. Trigger ACME validation ─────────────────────────────────────
        foreach ($challenges as $domainValidation) {
            $api->domainValidation()->start($account, $domainValidation, $challengeType, $this->localTest);
        }

        // ── 8. Poll until all challenges pass (or fail) ────────────────────
        $allPassed = $api->domainValidation()->allChallengesPassed($order);

        // ── 9. Clean up challenge files/records ────────────────────────────
        foreach ($validationData as $item) {
            [$token] = $this->extractTokenAndKeyAuth($item, $challengeType);
            $this->challengeHandler->cleanup($item['identifier'], $token);
        }

        if (!$allPassed) {
            throw new LetsEncryptClientException(
                'Domain validation failed — one or more challenges did not pass.'
            );
        }

        // ── 10. Generate certificate private key ───────────────────────────
        $certKey    = OpenSsl::generateKey($this->certKeyType);
        $certKeyPem = OpenSsl::openSslKeyToString($certKey);

        // ── 11. Generate CSR ───────────────────────────────────────────────
        $csr = OpenSsl::generateCsr($this->domains, $certKey);

        // ── 12. Finalize order ─────────────────────────────────────────────
        if (!$api->order()->finalize($order, $csr)) {
            throw new LetsEncryptClientException('Order finalization failed.');
        }

        // ── 13. Poll until order transitions processing → valid ────────────
        $order = $api->order()->waitUntilValid($order);

        // ── 14. Download certificate bundle ───────────────────────────────
        $bundle = $api->certificate()->getBundle($order);

        // ── 15. Parse expiry date from the DER-encoded certificate ─────────
        $parsed    = openssl_x509_parse($bundle->certificate);
        $expiresAt = isset($parsed['validTo_time_t'])
            ? (new DateTimeImmutable())->setTimestamp((int) $parsed['validTo_time_t'])
            : new DateTimeImmutable('+90 days');

        // ── 16. Build and persist the stored certificate ───────────────────
        $stored = new StoredCertificate(
            certificate: $bundle->certificate,
            privateKey:  $certKeyPem,
            fullchain:   $bundle->fullchain,
            caBundle:    $bundle->caBundle,
            issuedAt:    new DateTimeImmutable(),
            expiresAt:   $expiresAt,
            domains:     $this->domains,
        );

        if ($this->storage !== null) {
            $this->storage->saveCertificate($this->domains[0], $stored);
        }

        return $stored;
    }

    /**
     * Alias for issue() — forces a fresh certificate regardless of expiry.
     */
    public function renew(): StoredCertificate
    {
        return $this->issue();
    }

    /**
     * Issue only when the certificate is absent or expires within $daysBeforeExpiry days.
     * Returns the existing certificate if it is still valid.
     */
    public function issueOrRenew(int $daysBeforeExpiry = 30): StoredCertificate
    {
        if (!$this->needsRenewal($daysBeforeExpiry)) {
            // needsRenewal() returns false only when storage is set and the cert exists.
            return $this->storage->getCertificate($this->domains[0])
                ?? throw new LetsEncryptClientException('Certificate unexpectedly missing from storage.');
        }

        return $this->issue();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private function ariWindow(StoredCertificate $cert): ?RenewalWindow
    {
        if (empty($cert->caBundle)) {
            return null;
        }

        if (!preg_match('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~', $cert->caBundle, $m)) {
            return null;
        }

        try {
            return (new Api(provider: $this->provider, logger: $this->logger, httpClient: $this->httpClient))
                ->renewalInfo()
                ->get($cert->certificate, $m[1]);
        } catch (\Throwable) {
            return null;
        }
    }

    private function validate(): void
    {
        if (empty($this->domains)) {
            throw new LetsEncryptClientException(
                'No domains configured. Call ->domains() before issuing a certificate.'
            );
        }

        if ($this->challengeHandler === null) {
            throw new LetsEncryptClientException(
                'No challenge handler configured. Call ->challenge() before issuing a certificate.'
            );
        }
    }

    private function detectChallengeType(): AuthorizationChallengeEnum
    {
        foreach (AuthorizationChallengeEnum::cases() as $type) {
            if ($this->challengeHandler->supports($type)) {
                return $type;
            }
        }

        throw new LetsEncryptClientException(
            'The configured challenge handler does not support any known challenge type.'
        );
    }

    /**
     * Returns [token, keyAuthorization] from a getValidationData() item.
     */
    private function extractTokenAndKeyAuth(array $item, AuthorizationChallengeEnum $type): array
    {
        return match ($type) {
            AuthorizationChallengeEnum::HTTP        => [$item['filename'], $item['content']],
            AuthorizationChallengeEnum::DNS,
            AuthorizationChallengeEnum::DNS_PERSIST => [$item['name'],     $item['value']],
        };
    }
}
