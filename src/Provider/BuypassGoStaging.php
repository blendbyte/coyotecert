<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

class BuypassGoStaging extends AbstractProvider
{
    public function getDirectoryUrl(): string
    {
        return 'https://api.test4.buypass.no/acme/directory';
    }

    public function getDisplayName(): string
    {
        return 'Buypass Go SSL (Staging)';
    }

    public function isEabRequired(): bool
    {
        return false;
    }

    public function getEabCredentials(string $email): ?EabCredentials
    {
        return null;
    }
}
