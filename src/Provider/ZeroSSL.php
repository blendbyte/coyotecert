<?php

declare(strict_types=1);

namespace CoyoteCert\Provider;

use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Support\Arr;

class ZeroSSL extends AbstractProvider
{
    public function __construct(
        #[\SensitiveParameter]
        private readonly ?string $apiKey = null,
        private readonly ?string $eabKid = null,
        private readonly ?string $eabHmac = null,
    ) {}

    public function getDirectoryUrl(): string
    {
        return 'https://acme.zerossl.com/v2/DV90';
    }

    public function getSlug(): string
    {
        return 'zerossl';
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

    public function getCaaIdentifiers(): array
    {
        return ['sectigo.com', 'comodoca.com'];
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

        // Catch the warning of a failed connection: it contains the URL, API key included
        $error = null;
        set_error_handler(static function (int $errno, string $message) use (&$error): bool {
            $error = $message;

            return true;
        });

        try {
            $body = file_get_contents($url, false, $context);
        } finally {
            restore_error_handler();
        }

        // $http_response_header is populated by file_get_contents as a side-effect
        $httpCode = 0;
        if (!empty($http_response_header)) {
            if (preg_match('/HTTP\/\S+\s+(\d+)/', $http_response_header[0], $m)) {
                $httpCode = (int) $m[1];
            }
        }

        if ($body === false && $httpCode === 0) {
            throw new AcmeException(sprintf(
                'ZeroSSL EAB provisioning failed: %s',
                preg_replace('/access_key=[^&\s)]*/', 'access_key=***', $error ?? 'no response'),
            ));
        }

        if ($body === false || $httpCode !== 200) {
            throw new AcmeException(
                sprintf('ZeroSSL EAB provisioning failed (HTTP %d).', $httpCode),
            );
        }

        $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        $data = is_array($data) ? $data : [];
        $kid  = Arr::stringOrNull($data, 'eab_kid');
        $hmac = Arr::stringOrNull($data, 'eab_hmac_key');

        if (empty($data['success']) || !$kid || !$hmac) {
            throw new AcmeException(
                'ZeroSSL EAB provisioning returned an unexpected response.',
            );
        }

        return new EabCredentials($kid, $hmac);
    }
}
