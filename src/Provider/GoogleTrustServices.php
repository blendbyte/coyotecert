<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class GoogleTrustServices extends AbstractProvider
{
    /**
     * EAB credentials are obtained from the Google Cloud Console.
     * @see https://cloud.google.com/certificate-manager/docs/public-ca-tutorial
     */
    public function __construct(
        private readonly string $eabKid,
        private readonly string $eabHmac,
    ) {}

    public function getDirectoryUrl(): string
    {
        return 'https://dv.acme-v02.api.pki.goog/directory';
    }

    public function getSlug(): string
    {
        return 'google';
    }

    public function getDisplayName(): string
    {
        return 'Google Trust Services';
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
        return ['pki.goog'];
    }
}
