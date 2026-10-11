<?php

declare(strict_types=1);

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;

interface StorageInterface
{
    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(string $providerSlug): bool;

    public function getAccountKey(string $providerSlug): string;

    public function getAccountKeyType(string $providerSlug): KeyType;

    public function saveAccountKey(string $providerSlug, string $pem, KeyType $type): void;

    // ── Certificates ─────────────────────────────────────────────────────────

    public function hasCertificate(string $domain, KeyType $keyType): bool;

    public function getCertificate(string $domain, KeyType $keyType): ?StoredCertificate;

    /** Storage key is derived from $domain + the key type inside $cert. */
    public function saveCertificate(string $domain, StoredCertificate $cert): void;

    /** No-op when the domain/key-type combination is not found. */
    public function deleteCertificate(string $domain, KeyType $keyType): void;
}
