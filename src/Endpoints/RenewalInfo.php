<?php

namespace CoyoteCert\Endpoints;

use DateTimeImmutable;
use CoyoteCert\DTO\RenewalWindow;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Support\Base64;

class RenewalInfo extends Endpoint
{
    public function get(string $certPem, string $issuerPem): ?RenewalWindow
    {
        $baseUrl = $this->client->directory()->renewalInfo();

        if ($baseUrl === null) {
            return null;
        }

        $url      = rtrim($baseUrl, '/') . '/' . $this->certId($certPem, $issuerPem);
        $response = $this->client->getHttpClient()->get($url);

        if ($response->getHttpResponseCode() !== 200) {
            return null;
        }

        $body = $response->jsonBody();

        return new RenewalWindow(
            start:          new DateTimeImmutable($body['suggestedWindow']['start']),
            end:            new DateTimeImmutable($body['suggestedWindow']['end']),
            explanationUrl: $body['explanationURL'] ?? null,
        );
    }

    public function certId(string $certPem, string $issuerPem): string
    {
        $issuerSpki = $this->spkiDer(openssl_get_publickey($issuerPem));
        $issuerHash = Base64::urlSafeEncode(hash('sha256', $issuerSpki, true));

        $parsed = openssl_x509_parse($certPem);

        if ($parsed === false) {
            throw new CryptoException('Failed to parse certificate for ARI cert ID.');
        }

        $serialBin = hex2bin($parsed['serialNumberHex'] ?? '');

        if ($serialBin === false) {
            throw new CryptoException('Failed to decode certificate serial number.');
        }

        $serial = Base64::urlSafeEncode($serialBin);

        return $issuerHash . '.' . $serial;
    }

    private function spkiDer(mixed $publicKey): string
    {
        // "BEGIN PUBLIC KEY" PEM wraps raw SPKI DER — strip the headers to get the DER bytes
        $details = openssl_pkey_get_details($publicKey);

        if ($details === false) {
            throw new CryptoException('Failed to get issuer public key details.');
        }

        $pem = $details['key'];

        return base64_decode(implode('', array_map(
            'trim',
            array_filter(explode("\n", $pem), static fn (string $l): bool => !str_starts_with($l, '-----'))
        )));
    }
}
