<?php

namespace CoyoteCert\Support;

class JsonWebSignature
{
    public static function generate(
        array $payload,
        string $url,
        string $nonce,
        #[\SensitiveParameter] string $accountPrivateKey
    ): array {
        $privateKey = openssl_pkey_get_private($accountPrivateKey);
        $details    = openssl_pkey_get_details($privateKey);
        $isEc       = $details['type'] === OPENSSL_KEYTYPE_EC;

        [$alg, $digest, $sigLen] = $isEc
            ? self::ecParams($details['ec']['curve_name'])
            : ['RS256', 'SHA256', null];

        $protected = [
            'alg'   => $alg,
            'jwk'   => JsonWebKey::compute($accountPrivateKey),
            'nonce' => $nonce,
            'url'   => $url,
        ];

        $payload64   = Base64::urlSafeEncode(str_replace('\\/', '/', json_encode($payload, JSON_THROW_ON_ERROR)));
        $protected64 = Base64::urlSafeEncode(json_encode($protected, JSON_THROW_ON_ERROR));

        openssl_sign($protected64.'.'.$payload64, $signed, $privateKey, $digest);

        if ($isEc) {
            $signed = self::derToRaw($signed, $sigLen);
        }

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode($signed),
        ];
    }

    /** @return array{0: string, 1: string, 2: int} [alg, digest, componentLen] */
    private static function ecParams(string $curveName): array
    {
        return match ($curveName) {
            'prime256v1' => ['ES256', 'SHA256', 32],
            'secp384r1'  => ['ES384', 'SHA384', 48],
            default      => throw new \RuntimeException("Unsupported EC curve: {$curveName}"),
        };
    }

    private static function derToRaw(string $der, int $componentLen): string
    {
        // DER ECDSA: 0x30 [len] 0x02 [r-len] [r] 0x02 [s-len] [s]
        $pos  = 2;
        $rLen = ord($der[$pos + 1]);
        $r    = substr($der, $pos + 2, $rLen);
        $pos += 2 + $rLen;
        $sLen = ord($der[$pos + 1]);
        $s    = substr($der, $pos + 2, $sLen);

        return str_pad(ltrim($r, "\x00"), $componentLen, "\x00", STR_PAD_LEFT)
             . str_pad(ltrim($s, "\x00"), $componentLen, "\x00", STR_PAD_LEFT);
    }
}
