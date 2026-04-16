<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\Api;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\KeyId;

abstract class Endpoint
{
    public function __construct(protected Api $client)
    {
    }

    /**
     * @param array<string, mixed>|null $payload
     * @return array<string, string>
     */
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
    /** @param array<string, mixed>|null $payload */
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
            && ($response->jsonBody()['type'] ?? '') === 'urn:ietf:params:acme:error:badNonce';
    }

    protected function throwError(Response $response, string $defaultMessage): never
    {
        $message = $response->jsonBody()['detail'] ?? $defaultMessage;
        $this->logResponse('error', $message, $response);

        throw new AcmeException($message);
    }

    protected function getAccountPrivateKey(): string
    {
        return $this->client->localAccount()->getPrivateKey();
    }

    /**
     * Seconds to wait before the next polling attempt.
     *
     * Respects the ACME server's Retry-After header when present; otherwise
     * applies exponential back-off (baseDelay * 2^attempt) capped at 64 s.
     *
     * @param int $attempt   Zero-based attempt index for the back-off exponent.
     * @param int $baseDelay Initial delay in seconds (used when no header is set).
     */
    protected function retryAfterDelay(Response $response, int $attempt, int $baseDelay): int
    {
        $retryAfter = (int) $response->getHeader('retry-after', 0);

        return $retryAfter > 0
            ? $retryAfter
            : (int) min($baseDelay * (2 ** $attempt), 64);
    }

    /** @param array<string, mixed> $additionalContext */
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
