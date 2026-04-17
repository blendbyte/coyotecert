<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class CustomProvider extends AbstractProvider
{
    /**
     * Use any ACME-compliant CA.
     *
     * @param string $directoryUrl Full directory URL of the CA.
     * @param string $displayName Human-readable name (used in logs).
     * @param string|null $eabKid EAB key ID if required by the CA.
     * @param string|null $eabHmac EAB HMAC key if required by the CA.
     * @param bool $verifyTls Whether to verify the CA's TLS certificate.
     */
    public function __construct(
        private readonly string  $directoryUrl,
        private readonly string  $displayName = 'Custom CA',
        private readonly ?string $eabKid = null,
        private readonly ?string $eabHmac = null,
        private readonly bool    $verifyTls = true,
        private readonly bool    $profilesSupported = false,
    ) {}

    public function getDirectoryUrl(): string
    {
        return $this->directoryUrl;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function isEabRequired(): bool
    {
        return $this->eabKid !== null;
    }

    public function getEabCredentials(string $email): ?EabCredentials
    {
        if ($this->eabKid !== null && $this->eabHmac !== null) {
            return new EabCredentials($this->eabKid, $this->eabHmac);
        }

        return null;
    }

    public function supportsProfiles(): bool
    {
        return $this->profilesSupported;
    }

    public function verifyTls(): bool
    {
        return $this->verifyTls;
    }
}
