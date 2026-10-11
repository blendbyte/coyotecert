<?php

declare(strict_types=1);

namespace CoyoteCert\DTO;

use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Response;

readonly class CertificateBundleData
{
    public function __construct(
        public string $certificate,
        public string $fullchain,
        public string $caBundle,
    ) {}

    public static function fromResponse(Response $response): CertificateBundleData
    {
        if (!preg_match_all(
            '~(-----BEGIN\sCERTIFICATE-----[\s\S]+?-----END\sCERTIFICATE-----)~i',
            $response->rawBody(),
            $matches,
        )) {
            throw new AcmeException('Certificate response contained no PEM blocks.');
        }

        $certificate  = $matches[0][0];
        $matchesCount = count($matches[0]);
        $fullchain    = $certificate . "\n";
        $caBundle     = '';

        for ($i = 1; $i < $matchesCount; $i++) {
            $caBundle  .= $matches[0][$i] . "\n";
            $fullchain .= $matches[0][$i] . "\n";
        }

        return new self(certificate: $certificate, fullchain: $fullchain, caBundle: $caBundle);
    }
}
