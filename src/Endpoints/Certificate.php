<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\CertificateBundleData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Support\Base64;

class Certificate extends Endpoint
{
    public function getBundle(OrderData $orderData): CertificateBundleData
    {
        if ($orderData->certificateUrl === null) {
            throw new AcmeException('Order does not have a certificate URL yet.');
        }

        $response = $this->postSigned($orderData->certificateUrl, $orderData->accountUrl);

        if ($response->getHttpResponseCode() !== 200) {
            $this->logResponse('error', 'Failed to fetch certificate', $response);

            throw new AcmeException('Failed to fetch certificate.');
        }

        return CertificateBundleData::fromResponse($response);
    }

    public function revoke(string $pem, int $reason = 0): bool
    {
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
