<?php

declare(strict_types=1);

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;

/**
 * Volatile in-memory storage, useful for testing and one-shot scripts.
 * Nothing is persisted between requests.
 */
class InMemoryStorage implements StorageInterface
{
    /** @var array<string, array{pem: string, type: KeyType}> Keyed by provider slug. */
    private array $accounts = [];

    /** @var array<string, StoredCertificate> Keyed as "{domain}:{KeyType->value}". */
    private array $certificates = [];

    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(string $providerSlug): bool
    {
        return isset($this->accounts[$providerSlug]);
    }

    public function getAccountKey(string $providerSlug): string
    {
        if (!isset($this->accounts[$providerSlug])) {
            throw new StorageException('No account key in memory storage.');
        }

        return $this->accounts[$providerSlug]['pem'];
    }

    public function getAccountKeyType(string $providerSlug): KeyType
    {
        if (!isset($this->accounts[$providerSlug])) {
            throw new StorageException('No account key type in memory storage.');
        }

        return $this->accounts[$providerSlug]['type'];
    }

    public function saveAccountKey(string $providerSlug, string $pem, KeyType $type): void
    {
        $this->accounts[$providerSlug] = ['pem' => $pem, 'type' => $type];
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
