<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Enums\EabAlgorithm;

class CustomProvider extends AbstractProvider
{
    /**
     * Use any ACME-compliant CA.
     *
     * @param string $directoryUrl Full directory URL of the CA.
     * @param string $displayName Human-readable name (used in logs).
     * @param string|null $eabKid EAB key ID if required by the CA.
     * @param string|null $eabHmac EAB HMAC key if required by the CA.
     * @param bool $verifyTls Whether to verify the CA's TLS certificate.
     * @param EabAlgorithm $eabAlgorithm HMAC algorithm for EAB signing (default HS256).
     * @param string[] $caaIdentifiers CAA record values that authorise this CA (e.g. ['myca.com']).
     *                                 Leave empty to skip the CAA pre-check.
     */
    public function __construct(
        private readonly string       $directoryUrl,
        private readonly string       $displayName = 'Custom CA',
        private readonly ?string      $eabKid = null,
        private readonly ?string      $eabHmac = null,
        private readonly bool         $verifyTls = true,
        private readonly bool         $profilesSupported = false,
        private readonly EabAlgorithm $eabAlgorithm = EabAlgorithm::HS256,
        private readonly array        $caaIdentifiers = [],
    ) {}

    public function getDirectoryUrl(): string
    {
        return $this->directoryUrl;
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
