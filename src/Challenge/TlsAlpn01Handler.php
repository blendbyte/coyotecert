<?php

namespace CoyoteCert\Challenge;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

/**
 * Base class for tls-alpn-01 challenge handlers (RFC 8737).
 *
 * The CA connects to port 443 of the domain being validated and negotiates the
 * "acme-tls/1" ALPN protocol. The server must present a self-signed certificate
 * that contains a critical id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31)
 * whose value is the SHA-256 digest of the key authorisation, encoded as a
 * DER OCTET STRING (RFC 8737 §3).
 *
 * Extend this class, implement deploy() and cleanup() to control how your TLS
 * server serves (and stops serving) the validation certificate. Call
 * generateAcmeCertificate() inside deploy() to obtain the cert and key.
 *
 * Example:
 *
 *   class MyTlsAlpn01Handler extends TlsAlpn01Handler
 *   {
 *       public function deploy(string $domain, string $token, string $keyAuthorization): void
 *       {
 *           ['cert' => $certPem, 'key' => $keyPem] =
 *               $this->generateAcmeCertificate($domain, $keyAuthorization);
 *
 *           // Configure your web server to present $certPem/$keyPem for
 *           // acme-tls/1 connections on port 443, then reload it.
 *           MyServer::loadAcmeCert($domain, $certPem, $keyPem);
 *       }
 *
 *       public function cleanup(string $domain, string $token): void
 *       {
 *           MyServer::removeAcmeCert($domain);
 *       }
 *   }
 */
abstract class TlsAlpn01Handler implements ChallengeHandlerInterface
{
    final public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::TLS_ALPN;
    }

    abstract public function deploy(string $domain, string $token, string $keyAuthorization): void;

    abstract public function cleanup(string $domain, string $token): void;

    /**
     * Generate the self-signed ACME validation certificate required by RFC 8737.
     *
     * Returns an array with keys 'cert' (PEM certificate) and 'key' (PEM private key).
     * Pass these to your TLS server so it can present the certificate to the CA on
     * port 443 when the "acme-tls/1" ALPN protocol is negotiated.
     *
     * @return array{cert: string, key: string}
     * @throws ChallengeException
     */
    protected function generateAcmeCertificate(string $domain, string $keyAuthorization): array
    {
        // RFC 8737 §3: the extension value is SHA-256(keyAuthorization) as a DER OCTET STRING.
        $hash    = hash('sha256', $keyAuthorization, true);
        $derBody = "\x04\x20" . $hash; // OCTET STRING tag (0x04), length 32 (0x20), value
        $hexDer  = implode(':', str_split(bin2hex($derBody), 2));

        $tempFile = tmpfile();

        if ($tempFile === false) {
            throw new ChallengeException('Failed to create temporary config file for tls-alpn-01 certificate.');
        }

        fwrite($tempFile, $this->buildConfig($domain, $hexDer));

        $meta = stream_get_meta_data($tempFile);
        $uri  = $meta['uri'] ?? null;

        if ($uri === null) {
            fclose($tempFile);

            throw new ChallengeException('Failed to obtain temporary config file path for tls-alpn-01 certificate.');
        }

        try {
            return $this->generateCertAndKey($domain, $uri);
        } finally {
            fclose($tempFile);
        }
    }

    /** @return array{cert: string, key: string} */
    private function generateCertAndKey(string $domain, string $configPath): array
    {
        // private_key_bits is ignored for EC but some openssl.cnf configs enforce a minimum.
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'private_key_bits' => 2048]);

        if ($key === false) {
            throw new ChallengeException('Failed to generate EC key for tls-alpn-01 certificate.');
        }

        $csr = openssl_csr_new(
            ['commonName' => $domain],
            $key,
            ['config' => $configPath, 'x509_extensions' => 'v3_acme'],
        );

        if (!($csr instanceof \OpenSSLCertificateSigningRequest)) {
            throw new ChallengeException('Failed to generate CSR for tls-alpn-01 certificate.');
        }

        $cert = openssl_csr_sign($csr, null, $key, 1, ['config' => $configPath, 'x509_extensions' => 'v3_acme']);

        if ($cert === false) {
            throw new ChallengeException('Failed to sign tls-alpn-01 certificate.');
        }

        if (!openssl_x509_export($cert, $certPem)) {
            throw new ChallengeException('Failed to export tls-alpn-01 certificate.');
        }

        if (!openssl_pkey_export($key, $keyPem, null, ['config' => $configPath])) {
            throw new ChallengeException('Failed to export tls-alpn-01 private key.');
        }

        return ['cert' => $certPem, 'key' => $keyPem];
    }

    private function buildConfig(string $domain, string $hexDer): string
    {
        return sprintf(
            "[req]\ndistinguished_name=req_dn\nx509_extensions=v3_acme\nprompt=no\n\n"
            . "[req_dn]\nCN=%s\n\n"
            . "[v3_acme]\nsubjectAltName=DNS:%s\n1.3.6.1.5.5.7.1.31=critical,DER:%s\n",
            $domain,
            $domain,
            $hexDer,
        );
    }
}
