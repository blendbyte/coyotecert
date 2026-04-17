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
        #[\SensitiveParameter]
        string $accountPrivateKey,
        string $kid,
        string $url,
        string $nonce,
        ?array $payload = null,
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
            ? EcSigning::ecParamsFromCurve($details['ec']['curve_name'])
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

        if (!openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, $digest)) {
            throw new CryptoException('Failed to sign payload.');
        }

        if ($isEc && $sigLen !== null) {
            $signed = EcSigning::derToRaw($signed, $sigLen);
        }

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode($signed),
        ];
    }
}
