<?php

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Exceptions\AcmeException;

class ZeroSSL extends AbstractProvider
{
    /**
     * @param string|null $apiKey ZeroSSL API key for automatic EAB provisioning.
     * @param string|null $eabKid Pre-provisioned EAB key ID (alternative to apiKey).
     * @param string|null $eabHmac Pre-provisioned EAB HMAC key (alternative to apiKey).
     */
    public function __construct(
        private readonly ?string $apiKey = null,
        private readonly ?string $eabKid = null,
        private readonly ?string $eabHmac = null,
    ) {}

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

    private function provisionEab(string $email): EabCredentials
    {
        $url = 'https://api.zerossl.com/acme/eab-credentials-email?access_key=' . urlencode((string) $this->apiKey);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => "Content-Type: application/x-www-form-urlencoded\r\n",
                'content'       => http_build_query(['email' => $email]),
                'timeout'       => 15,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => true,
            ],
        ]);

        $body = file_get_contents($url, false, $context);

        // Parse HTTP status from $http_response_header (populated by file_get_contents)
        $httpCode = 0;
        if (!empty($http_response_header)) {
            if (preg_match('/HTTP\/\S+\s+(\d+)/', $http_response_header[0], $m)) {
                $httpCode = (int) $m[1];
            }
        }

        if ($body === false || $httpCode !== 200) {
            throw new AcmeException(
                sprintf('ZeroSSL EAB provisioning failed (HTTP %d).', $httpCode),
            );
        }

        $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (empty($data['success']) || empty($data['eab_kid']) || empty($data['eab_hmac_key'])) {
            throw new AcmeException(
                'ZeroSSL EAB provisioning returned an unexpected response.',
            );
        }

        return new EabCredentials($data['eab_kid'], $data['eab_hmac_key']);
    }
}
