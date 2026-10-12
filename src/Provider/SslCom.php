<?php

declare(strict_types=1);

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class SslCom extends AbstractProvider
{
    /** SSL.com's directories don't require EAB; pass credentials to link the account to your SSL.com account. */
    public function __construct(
        private readonly ?string $eabKid = null,
        #[\SensitiveParameter]
        private readonly ?string $eabHmac = null,
        private readonly bool    $ecc = false,
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
        return $this->eabKid !== null;
    }

    public function getEabCredentials(string $email): ?EabCredentials
    {
        return $this->eabKid !== null && $this->eabHmac !== null
            ? new EabCredentials($this->eabKid, $this->eabHmac)
            : null;
    }

    public function getCaaIdentifiers(): array
    {
        return ['ssl.com'];
    }
}
