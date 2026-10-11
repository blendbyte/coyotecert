<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;

class FilesystemStorage implements StorageInterface
{
    public function __construct(private readonly string $directory) {}

    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(string $providerSlug): bool
    {
        return file_exists($this->accountKeyPath($providerSlug))
            && file_exists($this->accountMetaPath($providerSlug));
    }

    public function getAccountKey(string $providerSlug): string
    {
        return $this->readFile($this->accountKeyPath($providerSlug));
    }

    public function getAccountKeyType(string $providerSlug): KeyType
    {
        $meta = json_decode($this->readFile($this->accountMetaPath($providerSlug)), true, 512, JSON_THROW_ON_ERROR);

        return KeyType::from($meta['key_type']);
    }

    public function saveAccountKey(string $providerSlug, string $pem, KeyType $type): void
    {
        $this->ensureDirectory();
        $this->writeFile($this->accountKeyPath($providerSlug), $pem);
        $this->writeFile(
            $this->accountMetaPath($providerSlug),
            json_encode(['key_type' => $type->value], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT),
        );
    }

    // ── Certificates ─────────────────────────────────────────────────────────

    public function hasCertificate(string $domain, KeyType $keyType): bool
    {
        return file_exists($this->certPath($domain, $keyType));
    }

    public function getCertificate(string $domain, KeyType $keyType): ?StoredCertificate
    {
        $path = $this->certPath($domain, $keyType);

        if (!file_exists($path)) {
            return null;
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
        $base = $this->pemBase($domain, $cert->keyType);
        $this->writeFile($base . 'certificate.pem', $cert->certificate, public: true);
        $this->writeFile($base . 'private_key.pem', $cert->privateKey);
        $this->writeFile($base . 'fullchain.pem', $cert->fullchain, public: true);
        $this->writeFile($base . 'ca.pem', $cert->caBundle, public: true);
    }

    public function deleteCertificate(string $domain, KeyType $keyType): void
    {
        $path = $this->certPath($domain, $keyType);

        if (!file_exists($path)) {
            return;
        }

        unlink($path);
        $base = $this->pemBase($domain, $keyType);
        foreach (['certificate.pem', 'private_key.pem', 'fullchain.pem', 'ca.pem'] as $file) {
            $p = $base . $file;
            if (file_exists($p)) {
                unlink($p);
            }
        }
    }

    // ── Paths ─────────────────────────────────────────────────────────────────

    private function accountKeyPath(string $providerSlug): string
    {
        return $this->dir() . 'account-' . $providerSlug . '.pem';
    }

    private function accountMetaPath(string $providerSlug): string
    {
        return $this->dir() . 'account-' . $providerSlug . '.json';
    }

    private function certPath(string $domain, KeyType $keyType): string
    {
        return $this->pemBase($domain, $keyType) . 'cert.json';
    }

    private function pemBase(string $domain, KeyType $keyType): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._\-]/', '_', $domain);

        return $this->dir() . $safe . '.' . $keyType->value . '.';
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

    /**
     * Write atomically: a temp file in the same directory is renamed over the target, so a
     * reader (or a web server reload) never sees a half-written file. Files are owner-only
     * unless $public: that covers the keys and cert.json, which embeds the private key.
     */
    private function writeFile(string $path, string $contents, bool $public = false): void
    {
        $dir = dirname($path);

        // Pre-check writability to avoid PHP warnings from tempnam()/rename()
        if (!is_writable($dir)) {
            throw new StorageException(
                sprintf('Could not write storage file "%s".', $path),
            );
        }

        // tempnam() creates the file with mode 0600, so a key is never readable by others
        $tmp = tempnam($dir, '.coyote-');

        if ($tmp === false || file_put_contents($tmp, $contents) === false) {
            throw new StorageException(sprintf('Could not write storage file "%s".', $path));
        }

        chmod($tmp, $public ? 0o644 : 0o600);

        if (!rename($tmp, $path)) {
            unlink($tmp);

            throw new StorageException(sprintf('Could not write storage file "%s".', $path));
        }
    }
}
