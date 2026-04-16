<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\CertificateBundleData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Exceptions\LetsEncryptClientException;
use CoyoteCert\Support\Base64;

class Certificate extends Endpoint
{
    public function getBundle(OrderData $orderData): CertificateBundleData
    {
        $response = $this->postSigned($orderData->certificateUrl, $orderData->accountUrl);

        if ($response->getHttpResponseCode() !== 200) {
            $this->logResponse('error', 'Failed to fetch certificate', $response);

            throw new LetsEncryptClientException('Failed to fetch certificate.');
        }

        return CertificateBundleData::fromResponse($response);
    }

    public function revoke(string $pem, int $reason = 0): bool
    {
        if (($data = openssl_x509_read($pem)) === false) {
            throw new LetsEncryptClientException('Could not parse the certificate.');
        }

        if (openssl_x509_export($data, $certificate) === false) {
            throw new LetsEncryptClientException('Could not export the certificate.');
        }

        preg_match('~-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----~s', $certificate, $matches);
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
