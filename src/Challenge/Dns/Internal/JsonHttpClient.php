<?php

namespace CoyoteCert\Challenge\Dns\Internal;

use CoyoteCert\Exceptions\ChallengeException;

/**
 * Shared JSON HTTP client for DNS provider API calls.
 *
 * Handles GET, POST, and DELETE requests with JSON payloads and responses.
 * Auth credentials are passed as $defaultHeaders at construction time so each
 * provider handler just calls request() without repeating auth logic.
 *
 * The protected send() method is the injection seam for unit tests: subclass
 * and override send() to replay fixture responses without making real HTTP calls.
 */
class JsonHttpClient
{
    /**
     * @param string $baseUrl Base URL prepended to every path (no trailing slash).
     * @param array<int, string> $defaultHeaders Headers sent with every request (e.g. auth).
     * @param int $timeout Per-request cURL timeout in seconds.
     */
    public function __construct(
        private readonly string $baseUrl,
        private readonly array $defaultHeaders = [],
        private readonly int $timeout = 15,
    ) {}

    /**
     * Execute a JSON API request and return the decoded response body.
     *
     * @param array<string, mixed>|null $payload JSON request body (POST only).
     * @param array<string, string>|null $queryParams URL query parameters (GET only).
     * @param array<int, string> $extraHeaders Per-request headers merged after defaults.
     * @return array<string, mixed>
     * @throws ChallengeException on connection error or HTTP 4xx/5xx.
     */
    public function request(
        string $method,
        string $path,
        ?array $payload = null,
        ?array $queryParams = null,
        array $extraHeaders = [],
    ): array {
        $url = $this->baseUrl . $path;

        if ($queryParams !== null) {
            $url .= '?' . http_build_query($queryParams);
        }

        $body    = $payload !== null ? json_encode($payload, JSON_THROW_ON_ERROR) : null;
        $headers = array_merge(
            ['Content-Type: application/json'],
            $this->defaultHeaders,
            $extraHeaders,
        );

        return $this->send($method, $url, $body, $headers);
    }

    /**
     * Execute the HTTP call via cURL and decode the JSON response.
     *
     * Marked protected so tests can subclass and bypass the network.
     *
     * @param array<int, string> $headers
     * @return array<string, mixed>
     */
    protected function send(string $method, string $url, ?string $body, array $headers): array
    {
        $ch = curl_init($url);

        if ($ch === false) {
            throw new ChallengeException('Failed to initialise cURL.');
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_USERAGENT      => 'blendbyte/coyotecert',
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);

            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
        } elseif ($method === 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        $raw    = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error  = curl_error($ch);
        curl_close($ch);

        if ($raw === false || $error !== '') {
            throw new ChallengeException("HTTP request failed: {$error}");
        }

        if ($status >= 400) {
            throw new ChallengeException(
                sprintf(
                    'API returned HTTP %d for %s %s.',
                    $status,
                    $method,
                    parse_url($url, PHP_URL_PATH) ?: $url,
                ),
            );
        }

        $decoded = (string) $raw;

        if ($decoded === '' || $decoded === 'null') {
            return [];
        }

        return json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
    }
}
