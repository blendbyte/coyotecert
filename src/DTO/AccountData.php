<?php

namespace CoyoteCert\DTO;

use CoyoteCert\Http\Response;
use CoyoteCert\Support\Url;

readonly class AccountData
{
    /**
     * @param array<string, mixed> $key
     * @param string[] $contact Contact URIs, e.g. ['mailto:admin@example.com']
     */
    public function __construct(
        public string  $id,
        public string  $url,
        public array   $key,
        public string  $status,
        public string  $agreement,
        public ?string $createdAt,
        public array   $contact = [],
    ) {}

    public static function fromResponse(Response $response): AccountData
    {
        $url = trim($response->getHeader('location', ''));

        return self::fromBody($url, $response->jsonBody());
    }

    /**
     * Build from an account URL and a response body array.
     * Used for update/deactivate responses where the Location header is absent.
     */
    /** @param array<string, mixed> $body */
    public static function fromBody(string $url, array $body): AccountData
    {
        return new self(
            id: Url::extractId($url),
            url: $url,
            key: $body['key'],
            status: $body['status'],
            agreement: $body['agreement'] ?? '',
            createdAt: $body['createdAt'] ?? null,
            contact: $body['contact']     ?? [],
        );
    }
}
