<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\CryptoException;

class CryptRSA
{
    /**
     * @return array{privateKey: string, publicKey: string}
     */
    public static function generate(): array
    {
        $pKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 4096,
        ]);

        if ($pKey === false) {
            throw new CryptoException('RSA keypair generation failed.');
        }

        if (!openssl_pkey_export($pKey, $privateKey)) {
            throw new CryptoException('RSA keypair export failed.');
        }

        $details = openssl_pkey_get_details($pKey);

        if ($details === false) {
            throw new CryptoException('Failed to get RSA key details.');
        }

        return [
            'privateKey' => $privateKey,
            'publicKey'  => $details['key'],
        ];
    }
}
