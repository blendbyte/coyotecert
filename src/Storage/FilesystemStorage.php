<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;

class FilesystemStorage implements StorageInterface
{
    /**
     * @param string $directory Path where account keys and certificates are stored.
     */
    public function __construct(private readonly string $directory) {}

    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(): bool
    {
        return file_exists($this->accountKeyPath())
            && file_exists($this->accountMetaPath());
    }

    public function getAccountKey(): string
    {
        return $this->readFile($this->accountKeyPath());
    }

    public function getAccountKeyType(): KeyType
    {
        $meta = json_decode($this->readFile($this->accountMetaPath()), true, 512, JSON_THROW_ON_ERROR);

        return KeyType::from($meta['key_type']);
    }

    public function saveAccountKey(string $pem, KeyType $type): void
    {
        $this->ensureDirectory();
        $this->writeFile($this->accountKeyPath(), $pem);
        $this->writeFile(
            $this->accountMetaPath(),
            json_encode(['key_type' => $type->value], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT),
        );
    }

    // ── Certificates ─────────────────────────────────────────────────────────

    public function hasCertificate(string $domain, KeyType $keyType): bool
    {
        if (file_exists($this->certPath($domain, $keyType))) {
            return true;
        }

        // Legacy path without key-type suffix — treated as present for migration.
        return file_exists($this->legacyCertPath($domain));
    }

    public function getCertificate(string $domain, KeyType $keyType): ?StoredCertificate
    {
        $path = $this->certPath($domain, $keyType);

        if (!file_exists($path)) {
            // Attempt transparent migration of a legacy single-cert file.
            $legacy = $this->legacyCertPath($domain);

            if (!file_exists($legacy)) {
                return null;
            }

            $data = json_decode($this->readFile($legacy), true, 512, JSON_THROW_ON_ERROR);
            $cert = StoredCertificate::fromArray($data);

            // Only migrate when the legacy cert's key type matches what's requested.
            if ($cert->keyType !== $keyType) {
                return null;
            }

            $this->ensureDirectory();
            $this->writeFile($path, json_encode($cert->toArray(), JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));
            unlink($legacy);

            return $cert;
        }

        $data = json_decode($this->readFile($path), true, 512, JSON_THROW_ON_ERROR);

        return StoredCertificate::fromArray($data);
    }

    public function saveCertificate(string $domain, StoredCertificate $cert): void
    {
        $this->ensureDirectory();
        $this->writeFile(
            $this->certPath($domain, $cert->keyType),
            json_encode($cert->toArray(), JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT),
        );
    }

    public function deleteCertificate(string $domain, KeyType $keyType): void
    {
        $path = $this->certPath($domain, $keyType);

        if (file_exists($path)) {
            unlink($path);

            return;
        }

        // Also remove a legacy file if it exists for this domain.
        $legacy = $this->legacyCertPath($domain);

        if (file_exists($legacy)) {
            unlink($legacy);
        }
    }

    // ── Paths ─────────────────────────────────────────────────────────────────

    private function accountKeyPath(): string
    {
        return $this->dir() . 'account.pem';
    }

    private function accountMetaPath(): string
    {
        return $this->dir() . 'account.json';
    }

    private function certPath(string $domain, KeyType $keyType): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._\-]/', '_', $domain);

        return $this->dir() . $safe . '.' . $keyType->value . '.cert.json';
    }

    /** Pre-v2 path — one cert per domain, no key-type suffix. */
    private function legacyCertPath(string $domain): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._\-]/', '_', $domain);

        return $this->dir() . $safe . '.cert.json';
    }

    private function dir(): string
    {
        return rtrim($this->directory, '/') . '/';
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function ensureDirectory(): void
    {
        $dir = $this->dir();

        if (file_exists(rtrim($dir, '/')) && !is_dir($dir)) {
            throw new StorageException(
                sprintf('Storage directory "%s" could not be created: path exists as a file.', $dir),
            );
        }

        if (!is_dir($dir) && !mkdir($dir, 0o700, true) && !is_dir($dir)) {
            throw new StorageException(
                sprintf('Storage directory "%s" could not be created.', $dir),
            );
        }
    }

    private function readFile(string $path): string
    {
        if (!file_exists($path)) {
            throw new StorageException(
                sprintf('Storage file "%s" does not exist.', $path),
            );
        }

        $contents = $this->readLocked($path);

        if ($contents === false) {
            throw new StorageException(
                sprintf('Could not read storage file "%s".', $path),
            );
        }

        return $contents;
    }

    /**
     * Read a file with a shared (read) lock to prevent reading a partially
     * written file when a concurrent writer holds LOCK_EX.
     */
    private function readLocked(string $path): string|false
    {
        $handle = fopen($path, 'rb');

        if ($handle === false) {
            return false;
        }

        if (!flock($handle, LOCK_SH)) {
            fclose($handle);

            return false;
        }

        $size     = filesize($path);
        $contents = $size > 0 ? fread($handle, $size) : '';

        flock($handle, LOCK_UN);
        fclose($handle);

        return $contents !== false ? $contents : false;
    }

    private function writeFile(string $path, string $contents): void
    {
        // Pre-check writability to avoid a PHP E_WARNING from file_put_contents.
        $checkTarget = file_exists($path) ? $path : dirname($path);
        if (!is_writable($checkTarget)) {
            throw new StorageException(
                sprintf('Could not write storage file "%s".', $path),
            );
        }

        file_put_contents($path, $contents, LOCK_EX);

        // Restrict private key files to owner-read-only.
        if (str_ends_with($path, '.pem')) {
            chmod($path, 0o600);
        }
    }
}
