<?php

namespace CoyoteCert\Challenge\Dns\Internal;

/**
 * Minimal AWS Signature Version 4 signer for Route53 API requests.
 *
 * Computes the Authorization, X-Amz-Date, Host, and Content-Type headers
 * required by AWS SigV4. The $now parameter is injectable so tests can
 * produce deterministic output without mocking global time.
 *
 * Reference: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */
class AwsSigV4Signer
{
    public function __construct(
        private readonly string $accessKeyId,
        private readonly string $secretAccessKey,
        private readonly string $region,
        private readonly string $service,
    ) {}

    /**
     * Sign a request and return the headers required by AWS SigV4.
     *
     * @return array<string, string>
     */
    public function sign(
        string $method,
        string $path,
        string $queryString,
        string $body,
        string $contentType,
        \DateTimeImmutable $now,
    ): array {
        $date     = $now->format('Ymd');
        $datetime = $now->format('Ymd\THis\Z');
        $host     = $this->service . '.amazonaws.com';

        // Canonical headers must be sorted by lowercase key.
        $canonicalHeaderMap = [
            'content-type' => $contentType,
            'host'         => $host,
            'x-amz-date'   => $datetime,
        ];

        ksort($canonicalHeaderMap);

        $canonicalHeaders = '';
        $signedHeaders    = '';
        foreach ($canonicalHeaderMap as $name => $value) {
            $canonicalHeaders .= $name . ':' . $value . "\n";
            $signedHeaders    .= ($signedHeaders !== '' ? ';' : '') . $name;
        }

        $canonicalRequest = implode("\n", [
            $method,
            $path,
            $queryString,
            $canonicalHeaders,
            $signedHeaders,
            hash('sha256', $body),
        ]);

        $credentialScope = implode('/', [$date, $this->region, $this->service, 'aws4_request']);

        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $datetime,
            $credentialScope,
            hash('sha256', $canonicalRequest),
        ]);

        $signingKey = hash_hmac(
            'sha256',
            'aws4_request',
            hash_hmac(
                'sha256',
                $this->service,
                hash_hmac(
                    'sha256',
                    $this->region,
                    hash_hmac('sha256', $date, 'AWS4' . $this->secretAccessKey, true),
                    true,
                ),
                true,
            ),
            true,
        );

        return [
            'Content-Type'  => $contentType,
            'Host'          => $host,
            'X-Amz-Date'    => $datetime,
            'Authorization' => sprintf(
                'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
                $this->accessKeyId,
                $credentialScope,
                $signedHeaders,
                hash_hmac('sha256', $stringToSign, $signingKey),
            ),
        ];
    }
}
