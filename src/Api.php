<?php

namespace CoyoteCert;

use CoyoteCert\Endpoints\Account;
use CoyoteCert\Endpoints\Certificate;
use CoyoteCert\Endpoints\Directory;
use CoyoteCert\Endpoints\DomainValidation;
use CoyoteCert\Endpoints\Nonce;
use CoyoteCert\Endpoints\Order;
use CoyoteCert\Endpoints\RenewalInfo;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Client;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Storage\StorageAccountAdapter;
use CoyoteCert\Storage\StorageInterface;
use Psr\Log\LoggerInterface;

class Api
{
    private ?string $cachedNonce  = null;
    private ?Directory $directory = null;

    public function __construct(
        private readonly AcmeProviderInterface $provider,
        private readonly ?StorageInterface     $storage = null,
        private ?LoggerInterface               $logger = null,
        private ?HttpClientInterface           $httpClient = null,
        private readonly KeyType               $accountKeyType = KeyType::EC_P256,
    ) {}

    public function storeNonce(string $nonce): void
    {
        $this->cachedNonce = $nonce;
    }

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

    public function getAccountKeyType(): KeyType
    {
        return $this->accountKeyType;
    }

    public function accountAdapter(): StorageAccountAdapter
    {
        if ($this->storage !== null) {
            return new StorageAccountAdapter($this->storage, $this->provider->getSlug());
        }

        throw new AcmeException(
            'No storage configured. Pass a StorageInterface to the Api constructor.',
        );
    }

    public function directory(): Directory
    {
        return $this->directory ??= new Directory($this);
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

    public function hasLogger(): bool
    {
        return $this->logger !== null;
    }

    /** @param array<string, mixed> $context */
    public function logger(string $level, string $message, array $context = []): void
    {
        if ($this->logger instanceof LoggerInterface) {
            $this->logger->log($level, $message, $context);
        }
    }
}
