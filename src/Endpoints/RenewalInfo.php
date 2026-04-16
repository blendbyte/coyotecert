<?php

namespace CoyoteCert\Endpoints;

use DateTimeImmutable;
use CoyoteCert\DTO\RenewalWindow;
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

        $body = $response->getBody();

        return new RenewalWindow(
            start:          new DateTimeImmutable($body['suggestedWindow']['start']),
            end:            new DateTimeImmutable($body['suggestedWindow']['end']),
            explanationUrl: $body['explanationURL'] ?? null,
        );
    }

    private function certId(string $certPem, string $issuerPem): string
    {
        $issuerSpki = $this->spkiDer(openssl_get_publickey($issuerPem));
        $issuerHash = Base64::urlSafeEncode(hash('sha256', $issuerSpki, true));

        $parsed = openssl_x509_parse($certPem);
        $serial = Base64::urlSafeEncode(hex2bin($parsed['serialNumberHex']));

        return $issuerHash . '.' . $serial;
    }

    private function spkiDer(mixed $publicKey): string
    {
        // "BEGIN PUBLIC KEY" PEM wraps raw SPKI DER — strip the headers to get the DER bytes
        $pem = openssl_pkey_get_details($publicKey)['key'];

        return base64_decode(implode('', array_map(
            'trim',
            array_filter(explode("\n", $pem), static fn ($l) => !str_starts_with($l, '-----'))
        )));
    }
}
