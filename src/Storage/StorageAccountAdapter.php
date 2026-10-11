<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;

/** @internal */
class StorageAccountAdapter
{
    public function __construct(
        private readonly StorageInterface $storage,
        private readonly string           $providerSlug,
    ) {}

    public function exists(): bool
    {
        return $this->storage->hasAccountKey($this->providerSlug);
    }

    public function getPrivateKey(): string
    {
        return $this->storage->getAccountKey($this->providerSlug);
    }

    public function savePrivateKey(string $pem, KeyType $keyType): void
    {
        $this->storage->saveAccountKey($this->providerSlug, $pem, $keyType);
    }
}
