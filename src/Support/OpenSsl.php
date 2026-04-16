<?php

namespace CoyoteCert\Support;

use OpenSSLAsymmetricKey;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\CryptoException;

class OpenSsl
{
    /**
     * Generate a key using a KeyType enum value.
     * This is the preferred method going forward; generatePrivateKey() is legacy.
     */
    public static function generateKey(KeyType $type): OpenSSLAsymmetricKey
    {
        $config = $type->isRsa()
            ? [
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => $type->bits(),
                'digest_alg'       => 'sha256',
            ]
            : [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name'       => $type->curveName(),
                // private_key_bits is ignored for EC (curve_name determines size) but some
                // openssl.cnf configs enforce a minimum; supply a value to satisfy them.
                'private_key_bits' => 2048,
            ];

        $key = openssl_pkey_new($config);

        if ($key === false) {
            throw new CryptoException(
                sprintf('Failed to generate %s key.', $type->value)
            );
        }

        return $key;
    }

    public static function generatePrivateKey(int $key_type = OPENSSL_KEYTYPE_RSA): OpenSSLAsymmetricKey
    {
        $key = match ($key_type) {
            OPENSSL_KEYTYPE_RSA => openssl_pkey_new([
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => 2048,
                'digest_alg' => 'sha256',
            ]),
            OPENSSL_KEYTYPE_EC => openssl_pkey_new([
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'private_key_bits' => 2048,
                'curve_name' => 'prime256v1',
            ]),
            default => throw new CryptoException('Invalid keytype'),
        };

        if ($key === false) {
            throw new CryptoException('Failed to generate private key.');
        }

        return $key;
    }

    public static function openSslKeyToString(OpenSSLAsymmetricKey $key): string
    {
        if (!openssl_pkey_export($key, $output)) {
            throw new CryptoException('Exporting SSL key failed.');
        }

        return trim($output);
    }

    /**
     * @param string[] $domains
     */
    public static function generateCsr(array $domains, OpenSSLAsymmetricKey $privateKey): string
    {
        $dn = ['commonName' => $domains[0]];

        $san = implode(',', array_map(function (string $dns): string {
            return 'DNS:' . $dns;
        }, $domains));

        $tempFile = tmpfile();

        if ($tempFile === false) {
            throw new CryptoException('Failed to create temporary file for CSR config.');
        }

        fwrite(
            $tempFile,
            'HOME = .
			RANDFILE = $ENV::HOME/.rnd
			[ req ]
			default_bits = 4096
			default_keyfile = privkey.pem
			distinguished_name = req_distinguished_name
			req_extensions = v3_req
			[ req_distinguished_name ]
			countryName = Country Name (2 letter code)
			[ v3_req ]
			basicConstraints = CA:FALSE
			subjectAltName = ' . $san . '
			keyUsage = nonRepudiation, digitalSignature, keyEncipherment'
        );

        $meta = stream_get_meta_data($tempFile);
        $uri  = $meta['uri'] ?? null;

        if ($uri === null) {
            fclose($tempFile);
            throw new CryptoException('Failed to obtain temporary file URI for CSR config.');
        }

        $csr = openssl_csr_new($dn, $privateKey, [
            'digest_alg' => 'sha256',
            'config' => $uri,
        ]);

        fclose($tempFile);

        if (!($csr instanceof \OpenSSLCertificateSigningRequest)) {
            throw new CryptoException('Generating CSR failed.');
        }

        if (!openssl_csr_export($csr, $out)) {
            throw new CryptoException('Exporting CSR failed.');
        }

        return trim($out);
    }
}
