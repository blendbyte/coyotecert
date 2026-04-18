<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class SslCom extends AbstractProvider
{
    /**
     * @param string $eabKid EAB key ID from your SSL.com account.
     * @param string $eabHmac EAB HMAC key from your SSL.com account.
     * @param bool $ecc Use the ECC endpoint instead of RSA.
     */
    public function __construct(
        private readonly string $eabKid,
        private readonly string $eabHmac,
        private readonly bool   $ecc = false,
    ) {}

    public function getDirectoryUrl(): string
    {
        return $this->ecc
            ? 'https://acme.ssl.com/sslcom-dv-ecc'
            : 'https://acme.ssl.com/sslcom-dv-rsa';
    }

    public function getSlug(): string
    {
        return 'sslcom';
    }

    public function getDisplayName(): string
    {
        return 'SSL.com' . ($this->ecc ? ' (ECC)' : ' (RSA)');
    }

    public function isEabRequired(): bool
    {
        return true;
    }

    public function getEabCredentials(string $email): ?EabCredentials
    {
        return new EabCredentials($this->eabKid, $this->eabHmac);
    }

    public function getCaaIdentifiers(): array
    {
        return ['ssl.com'];
    }
}
