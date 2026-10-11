<?php

declare(strict_types=1);

namespace CoyoteCert\DTO;

use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\Url;

readonly class AccountData
{
    /**
     * @param array<mixed> $key
     * @param list<string> $contact Contact URIs, e.g. ['mailto:admin@example.com']
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
        return self::fromBody($response->getHeaderLine('location'), $response->jsonBody());
    }

    /**
     * Build from an account URL and a response body array.
     * Used for update/deactivate responses where the Location header is absent.
     *
     * @param array<mixed> $body
     */
    public static function fromBody(string $url, array $body): AccountData
    {
        return new self(
            id: Url::extractId($url),
            url: $url,
            key: Arr::array($body, 'key'), // optional in RFC 8555 account objects
            status: Arr::string($body, 'status'),
            agreement: Arr::stringOrNull($body, 'agreement') ?? '',
            createdAt: Arr::stringOrNull($body, 'createdAt'),
            contact: Arr::strings($body, 'contact'),
        );
    }
}
