<?php

namespace CoyoteCert\Interfaces;

use CoyoteCert\Http\Response;

interface HttpClientInterface
{
    public function head(string $url): Response;

    public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response;

    public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response;
}
