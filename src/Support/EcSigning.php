<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\CryptoException;

/**
 * Shared EC signing utilities used by KeyId and JsonWebSignature.
 */
final class EcSigning
{
    /**
     * Convert a DER-encoded ECDSA signature to the raw R||S format required
     * for JWS (RFC 7518 §3.4).
     *
     * DER layout: 0x30 [seq-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
     */
    public static function derToRaw(string $der, int $componentLen): string
    {
        $len = strlen($der);

        // Minimum valid DER ECDSA sequence: 0x30 len 0x02 rLen r 0x02 sLen s
        if ($len < 8 || ord($der[0]) !== 0x30 || ord($der[2]) !== 0x02) {
            throw new CryptoException('Malformed DER-encoded ECDSA signature.');
        }

        $pos  = 2;
        $rLen = ord($der[$pos + 1]);

        if ($pos + 2 + $rLen + 2 > $len || ord($der[$pos + 2 + $rLen]) !== 0x02) {
            throw new CryptoException('Malformed DER-encoded ECDSA signature.');
        }

        $r    = substr($der, $pos + 2, $rLen);
        $pos += 2 + $rLen;
        $sLen = ord($der[$pos + 1]);

        if ($pos + 2 + $sLen > $len) {
            throw new CryptoException('Malformed DER-encoded ECDSA signature.');
        }

        $s = substr($der, $pos + 2, $sLen);

        return str_pad(ltrim($r, "\x00"), $componentLen, "\x00", STR_PAD_LEFT)
             . str_pad(ltrim($s, "\x00"), $componentLen, "\x00", STR_PAD_LEFT);
    }

    /**
     * Extract [alg, digest, componentLen] for a given EC curve name.
     *
     * @return array{0: string, 1: string, 2: int}
     */
    public static function ecParamsFromCurve(string $curveName): array
    {
        return match ($curveName) {
            'prime256v1' => ['ES256', 'SHA256', 32],
            'secp384r1'  => ['ES384', 'SHA384', 48],
            default      => throw new CryptoException("Unsupported EC curve: {$curveName}"),
        };
    }

    /**
     * Extract EC JWK parameters (crv, x, y) from an OpenSSL key.
     *
     * @param \OpenSSLAsymmetricKey $key
     * @return array{crv: string, x: string, y: string}
     */
    public static function ecParamsFromKey(\OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new CryptoException('Key is not an EC key.');
        }

        $crv = match ($details['ec']['curve_name']) {
            'prime256v1' => 'P-256',
            'secp384r1'  => 'P-384',
            default      => throw new CryptoException("Unsupported EC curve: {$details['ec']['curve_name']}"),
        };

        return [
            'crv' => $crv,
            'x'   => Base64::urlSafeEncode($details['ec']['x']),
            'y'   => Base64::urlSafeEncode($details['ec']['y']),
        ];
    }
}
