<?php

namespace CoyoteCert\DTO;

use CoyoteCert\Http\Response;
use CoyoteCert\Support\Url;

readonly class AccountData
{
    public function __construct(
        public string  $id,
        public string  $url,
        public array   $key,
        public string  $status,
        public string  $agreement,
        public ?string $createdAt,
        /** @var string[] Contact URIs, e.g. ['mailto:admin@example.com'] */
        public array   $contact = [],
    ) {
    }

    public static function fromResponse(Response $response): AccountData
    {
        $url = trim($response->getHeader('location', ''));

        return self::fromBody($url, $response->getBody());
    }

    /**
     * Build from an account URL and a response body array.
     * Used for update/deactivate responses where the Location header is absent.
     */
    public static function fromBody(string $url, array $body): AccountData
    {
        return new self(
            id:        Url::extractId($url),
            url:       $url,
            key:       $body['key'],
            status:    $body['status'],
            agreement: $body['agreement'] ?? '',
            createdAt: $body['createdAt'] ?? null,
            contact:   $body['contact'] ?? [],
        );
    }
}
