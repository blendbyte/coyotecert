<?php

namespace CoyoteCert;

use Psr\Log\LoggerInterface;
use CoyoteCert\Endpoints\Account;
use CoyoteCert\Endpoints\Certificate;
use CoyoteCert\Endpoints\RenewalInfo;
use CoyoteCert\Endpoints\Directory;
use CoyoteCert\Endpoints\DomainValidation;
use CoyoteCert\Endpoints\Nonce;
use CoyoteCert\Endpoints\Order;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Client;
use CoyoteCert\Interfaces\AcmeAccountInterface;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Storage\StorageAccountAdapter;
use CoyoteCert\Storage\StorageInterface;

class Api
{
    /** Cached nonce from the last ACME response's Replay-Nonce header. */
    private ?string $cachedNonce = null;

    public function __construct(
        private readonly AcmeProviderInterface $provider,
        private readonly ?StorageInterface     $storage         = null,
        private ?LoggerInterface               $logger          = null,
        private ?HttpClientInterface           $httpClient      = null,
        private readonly KeyType               $accountKeyType  = KeyType::EC_P256,
    ) {
    }

    /**
     * Store a nonce returned in a server response's Replay-Nonce header
     * so the next request can use it without a round-trip HEAD request.
     */
    public function storeNonce(string $nonce): void
    {
        $this->cachedNonce = $nonce;
    }

    /**
     * Consume and return the cached nonce, or null if none is available.
     */
    public function consumeCachedNonce(): ?string
    {
        $nonce             = $this->cachedNonce;
        $this->cachedNonce = null;

        return $nonce;
    }

    public function getProvider(): AcmeProviderInterface
    {
        return $this->provider;
    }

    public function accountAdapter(): AcmeAccountInterface
    {
        if ($this->storage !== null) {
            return new StorageAccountAdapter($this->storage, $this->accountKeyType);
        }

        throw new AcmeException(
            'No storage configured. Pass a StorageInterface to the Api constructor.'
        );
    }

    /**
     * @deprecated Use accountAdapter() instead.
     */
    public function localAccount(): AcmeAccountInterface
    {
        return $this->accountAdapter();
    }

    public function directory(): Directory
    {
        return new Directory($this);
    }

    public function nonce(): Nonce
    {
        return new Nonce($this);
    }

    public function account(): Account
    {
        return new Account($this);
    }

    public function order(): Order
    {
        return new Order($this);
    }

    public function domainValidation(): DomainValidation
    {
        return new DomainValidation($this);
    }

    public function certificate(): Certificate
    {
        return new Certificate($this);
    }

    public function renewalInfo(): RenewalInfo
    {
        return new RenewalInfo($this);
    }

    public function getHttpClient(): HttpClientInterface
    {
        if ($this->httpClient === null) {
            $this->httpClient = new Client(verifyTls: $this->provider->verifyTls());
        }

        return $this->httpClient;
    }

    public function setHttpClient(HttpClientInterface $httpClient): self
    {
        $this->httpClient = $httpClient;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /** @param array<string, mixed> $context */
    public function logger(string $level, string $message, array $context = []): void
    {
        if ($this->logger instanceof LoggerInterface) {
            $this->logger->log($level, $message, $context);
        }
    }
}
