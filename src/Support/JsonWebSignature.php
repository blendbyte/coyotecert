<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\CryptoException;

class JsonWebSignature
{
    /**
     * @param array<string, mixed> $payload
     * @return array<string, string>
     */
    public static function generate(
        array $payload,
        string $url,
        string $nonce,
        #[\SensitiveParameter]
        string $accountPrivateKey,
    ): array {
        $privateKey = openssl_pkey_get_private($accountPrivateKey);

        if ($privateKey === false) {
            throw new CryptoException('Cannot load private key.');
        }

        $details = openssl_pkey_get_details($privateKey);

        if ($details === false) {
            throw new CryptoException('Failed to get key details.');
        }

        $isEc = $details['type'] === OPENSSL_KEYTYPE_EC;

        if ($isEc) {
            [$alg, $digest, $sigLen] = EcSigning::ecParamsFromCurve($details['ec']['curve_name']);
        } else {
            $alg    = 'RS256';
            $digest = 'SHA256';
            $sigLen = null;
        }

        $protected = [
            'alg'   => $alg,
            'jwk'   => JsonWebKey::compute($accountPrivateKey),
            'nonce' => $nonce,
            'url'   => $url,
        ];

        $payload64   = Base64::urlSafeEncode(str_replace('\\/', '/', json_encode($payload, JSON_THROW_ON_ERROR)));
        $protected64 = Base64::urlSafeEncode(json_encode($protected, JSON_THROW_ON_ERROR));

        if (!openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, $digest)) {
            throw new CryptoException('Failed to sign payload.');
        }

        if ($isEc) {
            $signed = EcSigning::derToRaw($signed, $sigLen);
        }

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode($signed),
        ];
    }

    /**
     * Convert a DER-encoded ECDSA signature to raw R||S format.
     * Kept as a public proxy for backward compatibility.
     */
    public static function derToRaw(string $der, int $componentLen): string
    {
        return EcSigning::derToRaw($der, $componentLen);
    }
}
