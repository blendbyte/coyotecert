<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Interfaces\AcmeAccountInterface;
use CoyoteCert\Support\OpenSsl;

/**
 * Internal adapter that makes a StorageInterface look like an AcmeAccountInterface.
 *
 * This is used by Api::localAccount() so that all existing endpoint classes
 * continue to work without modification.
 *
 * @internal
 */
class StorageAccountAdapter implements AcmeAccountInterface
{
    public function __construct(
        private readonly StorageInterface $storage,
        private readonly KeyType          $keyType = KeyType::RSA_2048,
    ) {
    }

    public function getPrivateKey(): string
    {
        return $this->storage->getAccountKey();
    }

    public function getPublicKey(): string
    {
        $privateKey = openssl_pkey_get_private($this->getPrivateKey());
        $details    = openssl_pkey_get_details($privateKey);

        return $details['key'];
    }

    public function exists(): bool
    {
        return $this->storage->hasAccountKey();
    }

    public function generateNewKeys(string $keyType = 'RSA'): bool
    {
        $key = OpenSsl::generateKey($this->keyType);
        $pem = OpenSsl::openSslKeyToString($key);
        $this->storage->saveAccountKey($pem, $this->keyType);

        return true;
    }

    public function savePrivateKey(string $pem, \CoyoteCert\Enums\KeyType $keyType): void
    {
        $this->storage->saveAccountKey($pem, $keyType);
    }
}
