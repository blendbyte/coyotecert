<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\Api;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\AuthException;
use CoyoteCert\Exceptions\RateLimitException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\KeyId;

abstract class Endpoint
{
    public function __construct(protected Api $client) {}

    /**
     * @param array<string, mixed>|null $payload
     * @return array<string, string>
     */
    protected function createKeyId(string $accountUrl, string $url, ?array $payload = null): array
    {
        return KeyId::generate(
            $this->client->accountAdapter()->getPrivateKey(),
            $accountUrl,
            $url,
            $this->client->nonce()->getNew(),
            $payload,
        );
    }

    /**
     * Sign and POST, retrying once on badNonce (RFC 8555 §6.5).
     * Each call to $this->createKeyId() fetches a fresh nonce, so the retry
     * automatically gets a new one from the server.
     * The Replay-Nonce from each response is cached for the next request.
     */
    /** @param array<string, mixed>|null $payload */
    protected function postSigned(string $url, string $accountUrl, ?array $payload = null): Response
    {
        $send = fn() => $this->client->getHttpClient()->post(
            $url,
            $this->createKeyId($accountUrl, $url, $payload),
        );

        $response = $send();
        $this->cacheResponseNonce($response);

        if ($this->isBadNonce($response)) {
            $response = $send();
            $this->cacheResponseNonce($response);
        }

        return $response;
    }

    /**
     * If the response contains a Replay-Nonce header, cache it so the next
     * request avoids an extra HEAD round-trip.
     */
    private function cacheResponseNonce(Response $response): void
    {
        $nonce = $response->getHeader('replay-nonce', '');

        if (is_string($nonce) && $nonce !== '') {
            $this->client->storeNonce(trim($nonce));
        }
    }

    protected function isBadNonce(Response $response): bool
    {
        return $response->getHttpResponseCode()      === 400
            && ($response->jsonBody()['type'] ?? '') === 'urn:ietf:params:acme:error:badNonce';
    }

    /** @param array<string, mixed> $additionalContext */
    protected function throwError(Response $response, string $defaultMessage, array $additionalContext = []): never
    {
        $this->logResponse('error', $response->jsonBody()['detail'] ?? $defaultMessage, $response, $additionalContext);

        throw $this->createException($response, $defaultMessage);
    }

    /**
     * Build a typed exception from the response without logging.
     * Dispatches 401/403 → AuthException, 429 → RateLimitException (with Retry-After),
     * and attaches RFC 8555 §6.7 subproblems to any exception that carries them.
     */
    protected function createException(Response $response, string $defaultMessage): AcmeException
    {
        $body    = $response->jsonBody();
        $message = $body['detail'] ?? $defaultMessage;

        /** @var array<int, array<string, mixed>> $subproblems */
        $subproblems = $body['subproblems'] ?? [];

        return match ($response->getHttpResponseCode()) {
            401, 403 => new AuthException($message),
            429      => new RateLimitException($message, $this->parseRetryAfterSeconds($response)),
            default  => new AcmeException($message, $subproblems),
        };
    }

    protected function parseRetryAfterSeconds(Response $response): ?int
    {
        $value = $response->getHeader('retry-after', '');

        if (!is_string($value) || $value === '') {
            return null;
        }

        $seconds = (int) $value;

        return $seconds > 0 ? $seconds : null;
    }

    protected function getAccountPrivateKey(): string
    {
        return $this->client->accountAdapter()->getPrivateKey();
    }

    /**
     * Seconds to wait before the next polling attempt.
     *
     * Respects the ACME server's Retry-After header when present; otherwise
     * applies exponential back-off (baseDelay * 2^attempt) capped at 64 s.
     *
     * @param int $attempt Zero-based attempt index for the back-off exponent.
     * @param int $baseDelay Initial delay in seconds (used when no header is set).
     */
    protected function retryAfterDelay(Response $response, int $attempt, int $baseDelay): int
    {
        $retryAfter = (int) $response->getHeader('retry-after', 0);

        return $retryAfter > 0
            ? min($retryAfter, 64)
            : (int) min($baseDelay * (2 ** $attempt), 64);
    }

    /** @param array<string, mixed> $additionalContext */
    protected function logResponse(string $level, string $message, Response $response, array $additionalContext = []): void
    {
        $body = $response->jsonBody();

        $this->client->logger($level, $message, array_merge([
            'url'    => $response->getRequestedUrl(),
            'status' => $response->getHttpResponseCode(),
            'type'   => $body['type']   ?? null,
            'detail' => $body['detail'] ?? null,
        ], $additionalContext));
    }
}
