<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Enums\EabAlgorithm;

class CustomProvider extends AbstractProvider
{
    public function __construct(
        private readonly string       $directoryUrl,
        private readonly string       $displayName = 'Custom CA',
        private readonly ?string      $eabKid = null,
        private readonly ?string      $eabHmac = null,
        private readonly bool         $verifyTls = true,
        private readonly bool         $profilesSupported = false,
        private readonly EabAlgorithm $eabAlgorithm = EabAlgorithm::HS256,
        /** @var string[] */
        private readonly array        $caaIdentifiers = [],
    ) {}

    public function getDirectoryUrl(): string
    {
        return $this->directoryUrl;
    }

    public function getSlug(): string
    {
        $host = parse_url($this->directoryUrl, PHP_URL_HOST);
        $slug = preg_replace('/[^a-z0-9-]/', '-', strtolower(is_string($host) ? $host : 'custom'));
        $slug = trim((string) $slug, '-') ?: 'custom';

        self::assertValidSlug($slug);

        return $slug;
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
            return new EabCredentials($this->eabKid, $this->eabHmac, $this->eabAlgorithm);
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

    public function getCaaIdentifiers(): array
    {
        return $this->caaIdentifiers;
    }
}
