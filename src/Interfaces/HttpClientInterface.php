<?php

namespace CoyoteCert\Interfaces;

use CoyoteCert\Http\Response;

interface HttpClientInterface
{
    public function head(string $url): Response;

    /**
     * @param array<int, string> $headers
     * @param array<string, mixed> $arguments
     */
    public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response;

    /**
     * @param array<string, mixed> $payload
     * @param array<int, string> $headers
     */
    public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response;
}
