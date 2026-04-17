<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;

/**
 * Volatile in-memory storage — useful for testing and one-shot scripts.
 * Nothing is persisted between requests.
 */
class InMemoryStorage implements StorageInterface
{
    private ?string  $accountKey     = null;
    private ?KeyType $accountKeyType = null;

    /** @var array<string, StoredCertificate> Keyed as "{domain}:{KeyType->value}". */
    private array $certificates = [];

    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(): bool
    {
        return $this->accountKey !== null;
    }

    public function getAccountKey(): string
    {
        if ($this->accountKey === null) {
            throw new StorageException('No account key in memory storage.');
        }

        return $this->accountKey;
    }

    public function getAccountKeyType(): KeyType
    {
        if ($this->accountKeyType === null) {
            throw new StorageException('No account key type in memory storage.');
        }

        return $this->accountKeyType;
    }

    public function saveAccountKey(string $pem, KeyType $type): void
    {
        $this->accountKey     = $pem;
        $this->accountKeyType = $type;
    }

    // ── Certificates ─────────────────────────────────────────────────────────

    public function hasCertificate(string $domain, KeyType $keyType): bool
    {
        return isset($this->certificates[$this->certKey($domain, $keyType)]);
    }

    public function getCertificate(string $domain, KeyType $keyType): ?StoredCertificate
    {
        return $this->certificates[$this->certKey($domain, $keyType)] ?? null;
    }

    public function saveCertificate(string $domain, StoredCertificate $cert): void
    {
        $this->certificates[$this->certKey($domain, $cert->keyType)] = $cert;
    }

    public function deleteCertificate(string $domain, KeyType $keyType): void
    {
        unset($this->certificates[$this->certKey($domain, $keyType)]);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function certKey(string $domain, KeyType $keyType): string
    {
        return $domain . ':' . $keyType->value;
    }
}
