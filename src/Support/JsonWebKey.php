<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\LetsEncryptClientException;

class JsonWebKey
{
    public static function compute(
        #[\SensitiveParameter] string $accountKey
    ): array {
        $privateKey = openssl_pkey_get_private($accountKey);

        if ($privateKey === false) {
            throw new LetsEncryptClientException('Can not create private key.');
        }

        $details = openssl_pkey_get_details($privateKey);

        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            [$crv, $coordLen] = match ($details['ec']['curve_name']) {
                'prime256v1' => ['P-256', 32],
                'secp384r1'  => ['P-384', 48],
                default      => throw new LetsEncryptClientException("Unsupported EC curve: {$details['ec']['curve_name']}"),
            };

            return [
                'crv' => $crv,
                'kty' => 'EC',
                'x'   => Base64::urlSafeEncode(str_pad($details['ec']['x'], $coordLen, "\x00", STR_PAD_LEFT)),
                'y'   => Base64::urlSafeEncode(str_pad($details['ec']['y'], $coordLen, "\x00", STR_PAD_LEFT)),
            ];
        }

        return [
            'e'   => Base64::urlSafeEncode($details['rsa']['e']),
            'kty' => 'RSA',
            'n'   => Base64::urlSafeEncode($details['rsa']['n']),
        ];
    }

    public static function thumbprint(array $jwk): string
    {
        return Base64::urlSafeEncode(hash('sha256', json_encode($jwk, JSON_THROW_ON_ERROR), true));
    }
}
