<?php

declare(strict_types=1);

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\RenewalWindow;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\Base64;
use DateTimeImmutable;

class RenewalInfo extends Endpoint
{
    public function get(string $certPem): ?RenewalWindow
    {
        $baseUrl = $this->client->directory()->renewalInfo();

        if ($baseUrl === null) {
            return null;
        }

        $url      = rtrim($baseUrl, '/') . '/' . $this->certId($certPem);
        $response = $this->client->getHttpClient()->get($url);

        if ($response->getHttpResponseCode() !== 200) {
            return null;
        }

        $body   = $response->jsonBody();
        $window = Arr::array($body, 'suggestedWindow');
        $start  = new DateTimeImmutable(Arr::string($window, 'start'));
        $end    = new DateTimeImmutable(Arr::string($window, 'end'));

        // RFC 9773 §4.2: a window that ends before it starts is treated as no response
        if ($end <= $start) {
            return null;
        }

        return new RenewalWindow(start: $start, end: $end, explanationUrl: Arr::stringOrNull($body, 'explanationURL'));
    }

    /** RFC 9773 §4.1: base64url(AKI keyIdentifier) "." base64url(DER serial number). */
    public function certId(string $certPem): string
    {
        $parsed = openssl_x509_parse($certPem);

        if ($parsed === false) {
            throw new CryptoException('Failed to parse certificate for ARI cert ID.');
        }

        $aki = $parsed['extensions']['authorityKeyIdentifier'] ?? '';

        // OpenSSL 3 prints the bare hex; older versions prefix it with "keyid:"
        if (!preg_match('/^\s*(?:keyid:)?([0-9A-F]{2}(?::[0-9A-F]{2})*)\s*$/im', $aki, $m)) {
            throw new CryptoException('Certificate has no Authority Key Identifier, cannot build ARI cert ID.');
        }

        $keyId     = (string) hex2bin(str_replace(':', '', $m[1]));
        $serialHex = $parsed['serialNumberHex'] ?? '';
        $serial    = hex2bin(strlen($serialHex) % 2 === 1 ? '0' . $serialHex : $serialHex);

        if ($serial === false || $serial === '') {
            throw new CryptoException('Failed to decode certificate serial number.');
        }

        // DER INTEGER: a serial with the high bit set needs a leading zero byte to stay positive
        if (ord($serial[0]) >= 0x80) {
            $serial = "\x00" . $serial;
        }

        return Base64::urlSafeEncode($keyId) . '.' . Base64::urlSafeEncode($serial);
    }
}
