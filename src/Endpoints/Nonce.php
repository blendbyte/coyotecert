<?php

namespace CoyoteCert\Endpoints;

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

        return trim($response->getHeader('replay-nonce'));
    }
}
