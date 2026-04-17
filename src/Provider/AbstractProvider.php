<?php

namespace CoyoteCert\Provider;

abstract class AbstractProvider implements AcmeProviderInterface
{
    public function supportsProfiles(): bool
    {
        return false;
    }

    public function verifyTls(): bool
    {
        return true;
    }

    public function getCaaIdentifiers(): array
    {
        return [];
    }
}
