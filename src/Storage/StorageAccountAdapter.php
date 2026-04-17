<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Interfaces\AcmeAccountInterface;
use CoyoteCert\Support\OpenSsl;

/**
 * Internal adapter that makes a StorageInterface look like an AcmeAccountInterface.
 *
 * This is used by Api::accountAdapter() so that all existing endpoint classes
 * continue to work without modification.
 *
 * @internal
 */
class StorageAccountAdapter implements AcmeAccountInterface
{
    public function __construct(
        private readonly StorageInterface $storage,
        private readonly KeyType          $keyType = KeyType::EC_P256,
    ) {}

    public function getPrivateKey(): string
    {
        return $this->storage->getAccountKey();
    }

    public function getPublicKey(): string
    {
        $privateKey = openssl_pkey_get_private($this->getPrivateKey());

        if ($privateKey === false) {
            throw new CryptoException('Cannot load private key.');
        }

        $details = openssl_pkey_get_details($privateKey);

        if ($details === false) {
            throw new CryptoException('Failed to get key details.');
        }

        return $details['key'];
    }

    public function exists(): bool
    {
        return $this->storage->hasAccountKey();
    }

    /**
     * Generate and store a new key pair.
     *
     * When called without an explicit $keyTypeOverride, the key type set on
     * construction is used. Pass a $keyTypeOverride to use a different key type
     * for this single call without changing the adapter's default.
     *
     * Previously the $keyType parameter was silently ignored; now it is used.
     */
    public function generateNewKeys(?KeyType $keyTypeOverride = null): bool
    {
        $keyType = $keyTypeOverride ?? $this->keyType;
        $key     = OpenSsl::generateKey($keyType);
        $pem     = OpenSsl::openSslKeyToString($key);
        $this->storage->saveAccountKey($pem, $keyType);

        return true;
    }

    public function savePrivateKey(string $pem, \CoyoteCert\Enums\KeyType $keyType): void
    {
        $this->storage->saveAccountKey($pem, $keyType);
    }
}
