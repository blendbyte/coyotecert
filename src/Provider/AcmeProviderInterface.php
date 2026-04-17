<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;

interface AcmeProviderInterface
{
    /**
     * The full ACME directory URL (e.g. https://acme-v02.api.letsencrypt.org/directory).
     */
    public function getDirectoryUrl(): string;

    /**
     * Human-readable name of the CA (used in logs and error messages).
     */
    public function getDisplayName(): string;

    /**
     * Whether this CA requires External Account Binding on registration.
     */
    public function isEabRequired(): bool;

    /**
     * Return EAB credentials for the given email address, or null if the caller
     * must supply them manually (e.g. Google Trust Services).
     *
     * For ZeroSSL this auto-provisions credentials via their REST API.
     * For CAs without EAB this always returns null.
     */
    public function getEabCredentials(string $email): ?EabCredentials;

    /**
     * Whether this CA supports ACME Profiles (e.g. Let's Encrypt's shortlived, classic, tlsserver).
     * When false, the profile field is omitted from new-order requests.
     */
    public function supportsProfiles(): bool;

    /**
     * Whether to verify the CA's TLS certificate.
     * Should only be false for local Pebble test instances.
     */
    public function verifyTls(): bool;

    /**
     * CAA DNS record identifiers that authorise this CA to issue certificates
     * (e.g. ['letsencrypt.org'] for Let's Encrypt).
     *
     * Return an empty array to skip the CAA pre-check — appropriate for local
     * test CAs (Pebble) or custom CAs whose CAA identifier is unknown.
     *
     * @return string[]
     */
    public function getCaaIdentifiers(): array;
}
