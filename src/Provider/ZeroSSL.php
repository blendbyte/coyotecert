<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Exceptions\AcmeException;

class ZeroSSL implements AcmeProviderInterface
{
    /**
     * @param string|null $apiKey   ZeroSSL API key for automatic EAB provisioning.
     * @param string|null $eabKid   Pre-provisioned EAB key ID (alternative to apiKey).
     * @param string|null $eabHmac  Pre-provisioned EAB HMAC key (alternative to apiKey).
     */
    public function __construct(
        private readonly ?string $apiKey  = null,
        private readonly ?string $eabKid  = null,
        private readonly ?string $eabHmac = null,
    ) {
    }

    public function getDirectoryUrl(): string
    {
        return 'https://acme.zerossl.com/v2/DV90';
    }

    public function getDisplayName(): string
    {
        return 'ZeroSSL';
    }

    public function isEabRequired(): bool
    {
        return true;
    }

    public function getEabCredentials(string $email): ?EabCredentials
    {
        if ($this->eabKid !== null && $this->eabHmac !== null) {
            return new EabCredentials($this->eabKid, $this->eabHmac);
        }

        if ($this->apiKey !== null) {
            return $this->provisionEab($email);
        }

        return null;
    }

    public function supportsProfiles(): bool
    {
        return false;
    }

    public function verifyTls(): bool
    {
        return true;
    }

    private function provisionEab(string $email): EabCredentials
    {
        $url = 'https://api.zerossl.com/acme/eab-credentials-email?access_key=' . urlencode((string) $this->apiKey);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query(['email' => $email]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        $body     = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $httpCode !== 200) {
            throw new AcmeException(
                sprintf('ZeroSSL EAB provisioning failed (HTTP %d).', $httpCode)
            );
        }

        $data = json_decode((string) $body, true, 512, JSON_THROW_ON_ERROR);

        if (empty($data['success']) || empty($data['eab_kid']) || empty($data['eab_hmac_key'])) {
            throw new AcmeException(
                'ZeroSSL EAB provisioning returned an unexpected response.'
            );
        }

        return new EabCredentials($data['eab_kid'], $data['eab_hmac_key']);
    }
}
