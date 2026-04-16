<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\Api;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\KeyId;

abstract class Endpoint
{
    public function __construct(protected Api $client)
    {
    }

    protected function createKeyId(string $accountUrl, string $url, ?array $payload = null): array
    {
        return KeyId::generate(
            $this->client->localAccount()->getPrivateKey(),
            $accountUrl,
            $url,
            $this->client->nonce()->getNew(),
            $payload
        );
    }

    /**
     * Sign and POST, retrying once on badNonce (RFC 8555 §6.5).
     * Each call to $this->createKeyId() fetches a fresh nonce, so the retry
     * automatically gets a new one from the server.
     */
    protected function postSigned(string $url, string $accountUrl, ?array $payload = null): Response
    {
        $send = fn () => $this->client->getHttpClient()->post(
            $url,
            $this->createKeyId($accountUrl, $url, $payload)
        );

        $response = $send();

        if ($this->isBadNonce($response)) {
            $response = $send();
        }

        return $response;
    }

    protected function isBadNonce(Response $response): bool
    {
        return $response->getHttpResponseCode() === 400
            && is_array($response->getBody())
            && ($response->getBody()['type'] ?? '') === 'urn:ietf:params:acme:error:badNonce';
    }

    protected function getAccountPrivateKey(): string
    {
        return $this->client->localAccount()->getPrivateKey();
    }

    protected function logResponse(string $level, string $message, Response $response, array $additionalContext = []): void
    {
        $this->client->logger($level, $message, array_merge([
            'url' => $response->getRequestedUrl(),
            'status' => $response->getHttpResponseCode(),
            'headers' => $response->getHeaders(),
            'body' => $response->getBody(),
        ], $additionalContext));
    }
}
