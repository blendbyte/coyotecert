<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\Exceptions\AcmeException;

class Nonce extends Endpoint
{
    public function getNew(): string
    {
        // Use the cached nonce from the previous response if available,
        // avoiding an extra HEAD round-trip.
        $cached = $this->client->consumeCachedNonce();

        if ($cached !== null && $cached !== '') {
            return $cached;
        }

        $response = $this->client
            ->getHttpClient()
            ->head($this->client->directory()->newNonce());
        $nonce = $response->getHeader('replay-nonce');

        if (!is_string($nonce) || trim($nonce) === '') {
            throw new AcmeException(sprintf(
                'The CA returned no Replay-Nonce (HTTP %d from %s).',
                $response->getHttpResponseCode(),
                $this->client->directory()->newNonce(),
            ));
        }

        return trim($nonce);
    }
}
