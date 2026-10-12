<?php

declare(strict_types=1);

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Exceptions\StorageException;
use CoyoteCert\Support\Arr;

readonly class StoredCertificate
{
    /**
     * @param string[] $domains
     */
    public function __construct(
        public string             $certificate,
        public string             $privateKey,
        public string             $fullchain,
        public string             $caBundle,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
        public array              $domains,
        public KeyType            $keyType = KeyType::EC_P256,
        public ?string            $providerSlug = null,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'certificate'   => $this->certificate,
            'private_key'   => $this->privateKey,
            'fullchain'     => $this->fullchain,
            'ca_bundle'     => $this->caBundle,
            'issued_at'     => $this->issuedAt->format(\DateTimeInterface::ATOM),
            'expires_at'    => $this->expiresAt->format(\DateTimeInterface::ATOM),
            'domains'       => $this->domains,
            'key_type'      => $this->keyType->value,
            'provider_slug' => $this->providerSlug,
        ];
    }

    /** @throws StorageException when $json is not a readable stored certificate */
    public static function fromJson(string $json): self
    {
        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($data)) {
                throw new StorageException('Stored certificate data is not a JSON object.');
            }

            return self::fromArray($data);
        } catch (StorageException $e) {
            throw $e;
        } catch (\Throwable $e) {
            // Truncated JSON, a missing field, an unknown key type or a bad date
            throw new StorageException('Stored certificate data is unreadable: ' . $e->getMessage(), previous: $e);
        }
    }

    /** @param array<mixed> $data */
    public static function fromArray(array $data): self
    {
        $keyType = Arr::stringOrNull($data, 'key_type');

        return new self(
            certificate: Arr::string($data, 'certificate'),
            privateKey: Arr::string($data, 'private_key'),
            fullchain: Arr::string($data, 'fullchain'),
            caBundle: Arr::string($data, 'ca_bundle'),
            issuedAt: new \DateTimeImmutable(Arr::string($data, 'issued_at')),
            expiresAt: new \DateTimeImmutable(Arr::string($data, 'expires_at')),
            domains: Arr::strings($data, 'domains'),
            keyType: $keyType !== null ? KeyType::from($keyType) : KeyType::EC_P256, // pre-key-type records were EC P-256
            providerSlug: Arr::stringOrNull($data, 'provider_slug'),
        );
    }

    public function isExpired(): bool
    {
        return $this->expiresAt <= new \DateTimeImmutable();
    }

    public function expiresWithin(int $days): bool
    {
        return $this->daysUntilExpiry() <= $days;
    }

    public function remainingDays(): int
    {
        $diff = (new \DateTimeImmutable())->diff($this->expiresAt);

        return $diff->invert ? 0 : (int) $diff->days;
    }

    /**
     * Number of days until the certificate expires, counting partial days up
     * (ceiling). Returns a negative value when the certificate has already expired.
     */
    public function daysUntilExpiry(): int
    {
        return (int) ceil(($this->expiresAt->getTimestamp() - time()) / 86400);
    }

    /**
     * Returns true when this certificate covers all the requested domains.
     *
     * Wildcard matching: *.example.com covers sub.example.com but not
     * example.com itself (RFC 2818 §3.1).
     *
     * @param string[] $domains
     */
    public function isValidForDomains(array $domains): bool
    {
        $covered = $this->sans();

        foreach ($domains as $domain) {
            if (!$this->domainCoveredBy($domain, $covered)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check whether $domain is covered by any entry in $covered.
     *
     * @param string[] $covered
     */
    private function domainCoveredBy(string $domain, array $covered): bool
    {
        $domain = strtolower($domain);
        // OpenSSL prints IPv6 SANs expanded (2001:DB8:0:0:...), so IPs are compared in binary form
        $ip = filter_var($domain, FILTER_VALIDATE_IP) ? inet_pton($domain) : false;

        foreach ($covered as $entry) {
            $entry = strtolower($entry);

            if ($entry === $domain || ($ip !== false && filter_var($entry, FILTER_VALIDATE_IP) && inet_pton($entry) === $ip)) {
                return true;
            }

            // Wildcard: *.example.com covers sub.example.com
            if (str_starts_with($entry, '*.')) {
                $wildcard = substr($entry, 2); // e.g. "example.com"
                $suffix   = '.' . $wildcard;

                if (str_ends_with($domain, $suffix) && substr_count($domain, '.') === substr_count($wildcard, '.') + 1) {
                    return true;
                }
            }
        }

        return false;
    }

    // ── Certificate inspection ────────────────────────────────────────────────

    /** @return array<mixed> */
    private function parsedCertificate(): array
    {
        $parsed = openssl_x509_parse($this->certificate);

        if ($parsed === false) {
            throw new CryptoException('Failed to parse stored certificate.');
        }

        return $parsed;
    }

    /**
     * Subject Alternative Names parsed from the certificate PEM.
     * Returns both DNS names and IP addresses.
     *
     * @return string[]
     */
    public function sans(): array
    {
        $san = Arr::stringOrNull(Arr::array($this->parsedCertificate(), 'extensions'), 'subjectAltName') ?? '';

        if ($san === '') {
            return [];
        }

        $names = [];
        foreach (explode(',', $san) as $entry) {
            // Handles "DNS:example.com", "IP Address:1.2.3.4", "IP:1.2.3.4"
            if (preg_match('/^(?:DNS|IP(?:\s+Address)?):\s*(.+)$/i', trim($entry), $m)) {
                $names[] = trim($m[1]);
            }
        }

        return $names;
    }

    /**
     * Lowercase hex-encoded certificate serial number.
     */
    public function serialNumber(): string
    {
        return strtolower(Arr::stringOrNull($this->parsedCertificate(), 'serialNumberHex') ?? '');
    }

    /**
     * Authority Key Identifier as an uppercase colon-separated hex string
     * (e.g. "A1:B2:C3"), or null when the extension is absent.
     */
    public function authorityKeyId(): ?string
    {
        $ext = Arr::stringOrNull(Arr::array($this->parsedCertificate(), 'extensions'), 'authorityKeyIdentifier');

        if ($ext === null) {
            return null;
        }

        // openssl_x509_parse() returns "keyid:XX:XX:XX...\n" or similar
        if (preg_match('/keyid:\s*([0-9A-Fa-f:]+)/i', $ext, $m)) {
            return strtoupper(rtrim($m[1], ':'));
        }

        // Some PHP/OpenSSL versions return raw hex without the "keyid:" prefix
        if (preg_match('/^([0-9A-F]{2}(?::[0-9A-F]{2})+)/i', trim($ext), $m)) {
            return strtoupper($m[1]);
        }

        return null;
    }

    /**
     * Issuer Distinguished Name fields as returned by openssl_x509_parse().
     *
     * @return array<string, string> e.g. ['CN' => 'R12', 'O' => "Let's Encrypt", 'C' => 'US']
     */
    public function issuer(): array
    {
        return array_filter(Arr::array($this->parsedCertificate(), 'issuer'), is_string(...));
    }
}
