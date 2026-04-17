<?php

namespace CoyoteCert\DTO;

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
        $certificate = '';
        $fullchain   = '';
        $caBundle    = '';

        if (preg_match_all(
            '~(-----BEGIN\sCERTIFICATE-----[\s\S]+?-----END\sCERTIFICATE-----)~i',
            $response->rawBody(),
            $matches,
        )) {
            $certificate  = $matches[0][0];
            $matchesCount = count($matches[0]);

            if ($matchesCount > 1) {
                $fullchain = $matches[0][0] . "\n";

                for ($i = 1; $i < $matchesCount; $i++) {
                    $caBundle  .= $matches[0][$i] . "\n";
                    $fullchain .= $matches[0][$i] . "\n";
                }
            }
        }

        return new self(certificate: $certificate, fullchain: $fullchain, caBundle: $caBundle);
    }
}
