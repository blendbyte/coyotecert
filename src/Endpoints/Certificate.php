<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\CertificateBundleData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Support\Base64;

class Certificate extends Endpoint
{
    public function getBundle(OrderData $orderData, ?string $preferredChain = null): CertificateBundleData
    {
        if ($orderData->certificateUrl === null) {
            throw new AcmeException('Order does not have a certificate URL yet.');
        }

        $response = $this->postSigned($orderData->certificateUrl, $orderData->accountUrl);

        if ($response->getHttpResponseCode() !== 200) {
            $this->logResponse('error', 'Failed to fetch certificate', $response);

            throw new AcmeException('Failed to fetch certificate.');
        }

        $primary = CertificateBundleData::fromResponse($response);

        if ($preferredChain === null) {
            return $primary;
        }

        $linkHeader = $response->getHeader('link', '');
        $linkHeader = is_string($linkHeader) ? $linkHeader : '';

        foreach ($this->parseAlternateLinks($linkHeader) as $url) {
            $altResponse = $this->postSigned($url, $orderData->accountUrl);

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

    private function chainMatchesIssuer(CertificateBundleData $bundle, string $preferredChain): bool
    {
        if ($bundle->caBundle === '') {
            return false;
        }

        if (!preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $matches)) {
            return false;
        }

        foreach ($matches[1] as $certPem) {
            $parsed = openssl_x509_parse($certPem);
            $cn     = $parsed['subject']['CN'] ?? '';
            $o      = $parsed['subject']['O']  ?? '';

            if (stripos($cn, $preferredChain) !== false || stripos($o, $preferredChain) !== false) {
                return true;
            }
        }

        return false;
    }

    public function revoke(string $pem, int $reason = 0): bool
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
            $this->logResponse('error', 'Failed to revoke certificate', $response);
        }

        return $response->getHttpResponseCode() === 200;
    }
}
