<?php

declare(strict_types=1);

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

interface AcmeProviderInterface
{
    public function getDirectoryUrl(): string;

    /**
     * Short, filesystem-safe identifier (e.g. "letsencrypt", "zerossl").
     * Namespaces account keys in storage so different CAs never share a key.
     * Must match [a-z0-9][a-z0-9-]*[a-z0-9] — no leading/trailing hyphens.
     */
    public function getSlug(): string;

    public function getDisplayName(): string;

    /**
     * Whether to send EAB credentials. The directory's externalAccountRequired, when present,
     * decides whether missing credentials are an error.
     */
    public function isEabRequired(): bool;

    /**
     * Return EAB credentials for registration, or null if not applicable.
     * ZeroSSL auto-provisions credentials from an API key; pass email for that path.
     */
    public function getEabCredentials(string $email): ?EabCredentials;

    /** Fallback for CAs whose directory doesn't list its profiles (meta.profiles). */
    public function supportsProfiles(): bool;

    /** Set to false only for local test CAs (e.g. Pebble). */
    public function verifyTls(): bool;

    /**
     * CAA DNS record values that authorise this CA (e.g. ['letsencrypt.org']); the directory's
     * caaIdentities are added to them. Return an empty array to skip the CAA pre-check.
     *
     * @return string[]
     */
    public function getCaaIdentifiers(): array;
}
