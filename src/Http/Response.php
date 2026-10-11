<?php

declare(strict_types=1);

namespace CoyoteCert\Http;

readonly class Response
{
    /**
     * @param array<string, mixed> $headers
     * @param array<mixed>|string $body
     */
    public function __construct(
        private array $headers,
        private string $requestedUrl,
        private ?int $statusCode,
        private array|string $body,
    ) {}

    public function getHeader(string $name, mixed $default = null): mixed
    {
        return $this->headers[$name] ?? $default;
    }

    /** A header as a string, or '' when it is missing (like PSR-7's getHeaderLine()). */
    public function getHeaderLine(string $name): string
    {
        $value = $this->headers[$name] ?? '';

        return is_scalar($value) ? trim((string) $value) : '';
    }

    /** @return array<string, mixed> */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[$name]);
    }

    /** @return array<mixed>|string */
    public function getBody(): array|string
    {
        return $this->body;
    }

    /** @return array<mixed> */
    public function jsonBody(): array
    {
        return is_array($this->body) ? $this->body : [];
    }

    public function rawBody(): string
    {
        return is_string($this->body) ? $this->body : '';
    }

    public function getRequestedUrl(): string
    {
        return $this->requestedUrl;
    }

    public function getHttpResponseCode(): ?int
    {
        return $this->statusCode;
    }
}
