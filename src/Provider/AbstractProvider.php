<?php

namespace CoyoteCert\Provider;

abstract class AbstractProvider implements AcmeProviderInterface
{
    protected static function assertValidSlug(string $slug): void
    {
        if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/', $slug)) {
            throw new \InvalidArgumentException(
                "Provider slug must contain only lowercase letters, digits, and hyphens, and must not start or end with a hyphen: \"{$slug}\".",
            );
        }
    }

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
