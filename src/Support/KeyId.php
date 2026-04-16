<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\CryptoException;

class KeyId
{
    /**
     * @param array<string, mixed>|null $payload
     * @return array<string, string>
     */
    public static function generate(
        #[\SensitiveParameter] string $accountPrivateKey,
        string $kid,
        string $url,
        string $nonce,
        ?array $payload = null
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

        [$alg, $digest, $sigLen] = $isEc
            ? self::ecParams($details['ec']['curve_name'])
            : ['RS256', 'SHA256', null];

        $data = [
            'alg'   => $alg,
            'kid'   => $kid,
            'nonce' => $nonce,
            'url'   => $url,
        ];

        // null  → empty string (POST-as-GET per RFC 8555)
        // []    → '{}' (challenge response: empty JSON object per RFC 8555 §7.5.1)
        // [...] → JSON-encoded object
        $payloadStr = is_array($payload)
            ? str_replace('\\/', '/', empty($payload) ? '{}' : (string) json_encode($payload))
            : '';

        $payload64   = Base64::urlSafeEncode($payloadStr);
        $protected64 = Base64::urlSafeEncode((string) json_encode($data));

        if (!openssl_sign($protected64.'.'.$payload64, $signed, $privateKey, $digest)) {
            throw new CryptoException('Failed to sign payload.');
        }

        if ($isEc && $sigLen !== null) {
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
            default      => throw new \CoyoteCert\Exceptions\CryptoException("Unsupported EC curve: {$curveName}"),
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
