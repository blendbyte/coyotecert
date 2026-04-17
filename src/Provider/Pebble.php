<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class Pebble extends AbstractProvider
{
    /**
     * @param string $url       Full directory URL of your Pebble instance.
     * @param bool   $verifyTls Set to false to skip TLS verification (needed for self-signed Pebble certs).
     * @param bool   $eab       Enable if your Pebble instance is configured with EAB.
     * @param string|null $eabKid  EAB key ID if EAB is enabled.
     * @param string|null $eabHmac EAB HMAC key if EAB is enabled.
     */
    public function __construct(
        private readonly string  $url       = 'https://localhost:14000/dir',
        private readonly bool    $verifyTls = true,
        private readonly bool    $eab       = false,
        private readonly ?string $eabKid    = null,
        private readonly ?string $eabHmac   = null,
    ) {
    }

    public function getDirectoryUrl(): string
    {
        return $this->url;
    }

    public function getDisplayName(): string
    {
        return 'Pebble (local test CA)';
    }

    public function isEabRequired(): bool
    {
        return $this->eab;
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
        return true;
    }

    public function verifyTls(): bool
    {
        return $this->verifyTls;
    }
}
