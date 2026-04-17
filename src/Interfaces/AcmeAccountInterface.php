<?php

namespace CoyoteCert\Interfaces;

interface AcmeAccountInterface
{
    public function getPrivateKey(): string;

    public function getPublicKey(): string;

    public function exists(): bool;

    public function generateNewKeys(?\CoyoteCert\Enums\KeyType $keyTypeOverride = null): bool;

    /** Persist a specific private key PEM (used after a key rollover). */
    public function savePrivateKey(string $pem, \CoyoteCert\Enums\KeyType $keyType): void;
}
