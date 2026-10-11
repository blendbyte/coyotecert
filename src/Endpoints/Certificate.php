<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\CertificateBundleData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Support\Base64;

class Certificate extends Endpoint
{
    // RFC 8555 §7.4.2: the certificate is downloaded as a PEM chain, not JSON
    private const ACCEPT_PEM = 'Accept: application/pem-certificate-chain';

    public function getBundle(OrderData $orderData, ?string $preferredChain = null): CertificateBundleData
    {
        if ($orderData->certificateUrl === null) {
            throw new AcmeException('Order does not have a certificate URL yet.');
        }

        $response = $this->postSigned($orderData->certificateUrl, $orderData->accountUrl, headers: [self::ACCEPT_PEM]);

        if ($response->getHttpResponseCode() !== 200) {
            $this->logResponse('error', 'Failed to fetch certificate', $response);

            throw new AcmeException('Failed to fetch certificate.');
        }

        $primary = CertificateBundleData::fromResponse($response);

        if ($preferredChain === null || $this->chainMatchesIssuer($primary, $preferredChain)) {
            return $primary;
        }

        $linkHeader = $response->getHeader('link', '');
        $linkHeader = is_string($linkHeader) ? $linkHeader : '';

        foreach ($this->parseAlternateLinks($linkHeader) as $url) {
            $altResponse = $this->postSigned($url, $orderData->accountUrl, headers: [self::ACCEPT_PEM]);

            if ($altResponse->getHttpResponseCode() !== 200) {
                continue;
            }

            $candidate = CertificateBundleData::fromResponse($altResponse);

            if ($this->chainMatchesIssuer($candidate, $preferredChain)) {
                return $candidate;
            }
        }

        return $primary;
    }

    /** @return string[] */
    private function parseAlternateLinks(string $linkHeader): array
    {
        if ($linkHeader === '') {
            return [];
        }

        $urls = [];

        foreach (explode(',', $linkHeader) as $entry) {
            if (preg_match('~<([^>]+)>\s*;\s*rel\s*=\s*["\']?alternate["\']?~i', trim($entry), $m)) {
                $urls[] = $m[1];
            }
        }

        return $urls;
    }

    /**
     * Like certbot's --preferred-chain: the chain matches when its topmost certificate was
     * issued by $preferredChain (Common Name, case-insensitive), i.e. it leads to that root.
     */
    private function chainMatchesIssuer(CertificateBundleData $bundle, string $preferredChain): bool
    {
        if (!preg_match_all('~-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----~', $bundle->fullchain, $matches)) {
            return false;
        }

        $top    = openssl_x509_parse(end($matches[0]));
        $issuer = $top !== false ? ($top['issuer']['CN'] ?? '') : '';

        return strcasecmp(trim($issuer), trim($preferredChain)) === 0;
    }

    public function revoke(string $pem, int $reason = 0): void
    {
        if (!str_contains($pem, '-----BEGIN CERTIFICATE-----')) {
            throw new AcmeException('Could not parse the certificate.');
        }

        if (($data = openssl_x509_read($pem)) === false) {
            throw new AcmeException('Could not parse the certificate.');
        }

        if (openssl_x509_export($data, $certificate) === false) {
            throw new AcmeException('Could not export the certificate.');
        }

        if (!preg_match('~-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----~s', $certificate, $matches)) {
            throw new AcmeException('Could not extract certificate body.');
        }

        $certificate = trim(Base64::urlSafeEncode(base64_decode(trim($matches[1]))));

        $revokeUrl  = $this->client->directory()->revoke();
        $accountUrl = $this->client->account()->get()->url;
        $response   = $this->postSigned($revokeUrl, $accountUrl, [
            'certificate' => $certificate,
            'reason'      => $reason,
        ]);

        if ($response->getHttpResponseCode() !== 200) {
            $this->throwError($response, 'Failed to revoke certificate.');
        }
    }
}
