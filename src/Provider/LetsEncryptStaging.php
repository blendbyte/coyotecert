<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class LetsEncryptStaging extends AbstractProvider
{
    public function getDirectoryUrl(): string
    {
        return 'https://acme-staging-v02.api.letsencrypt.org/directory';
    }

    public function getSlug(): string
    {
        return 'letsencrypt-staging';
    }

    public function getDisplayName(): string
    {
        return "Let's Encrypt (Staging)";
    }

    public function isEabRequired(): bool
    {
        return false;
    }

    public function getEabCredentials(string $email): ?EabCredentials
    {
        return null;
    }

    public function supportsProfiles(): bool
    {
        return true;
    }

    public function getCaaIdentifiers(): array
    {
        return ['letsencrypt.org'];
    }
}
