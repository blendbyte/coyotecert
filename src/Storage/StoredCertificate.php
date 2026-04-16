<?php

namespace CoyoteCert\Storage;

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
    ) {
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'certificate' => $this->certificate,
            'private_key' => $this->privateKey,
            'fullchain'   => $this->fullchain,
            'ca_bundle'   => $this->caBundle,
            'issued_at'   => $this->issuedAt->format(\DateTimeInterface::ATOM),
            'expires_at'  => $this->expiresAt->format(\DateTimeInterface::ATOM),
            'domains'     => $this->domains,
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            certificate: $data['certificate'],
            privateKey:  $data['private_key'],
            fullchain:   $data['fullchain'],
            caBundle:    $data['ca_bundle'],
            issuedAt:    new \DateTimeImmutable($data['issued_at']),
            expiresAt:   new \DateTimeImmutable($data['expires_at']),
            domains:     $data['domains'],
        );
    }

    public function remainingDays(): int
    {
        $diff = (new \DateTimeImmutable())->diff($this->expiresAt);

        return $diff->invert ? 0 : (int) $diff->days;
    }

    // ── Certificate inspection ────────────────────────────────────────────────

    /**
     * Subject Alternative Names parsed from the certificate PEM.
     * Returns both DNS names and IP addresses.
     *
     * @return string[]
     */
    public function sans(): array
    {
        $parsed = openssl_x509_parse($this->certificate);
        $san    = $parsed['extensions']['subjectAltName'] ?? '';

        if (empty($san)) {
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
        return strtolower(openssl_x509_parse($this->certificate)['serialNumberHex'] ?? '');
    }

    /**
     * Authority Key Identifier as an uppercase colon-separated hex string
     * (e.g. "A1:B2:C3"), or null when the extension is absent.
     */
    public function authorityKeyId(): ?string
    {
        $parsed = openssl_x509_parse($this->certificate);
        $ext    = $parsed['extensions']['authorityKeyIdentifier'] ?? null;

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
     * @return array{CN?: string, O?: string, C?: string}
     */
    public function issuer(): array
    {
        return openssl_x509_parse($this->certificate)['issuer'] ?? [];
    }
}
