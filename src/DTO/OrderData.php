<?php

declare(strict_types=1);

namespace CoyoteCert\DTO;

use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\Url;

readonly class OrderData
{
    /**
     * @param list<array{type: string, value: string}> $identifiers
     * @param list<string> $domainValidationUrls
     */
    public function __construct(
        public string  $id,
        public string  $url,
        public string  $status,
        public ?string $expires,
        public array   $identifiers,
        public array   $domainValidationUrls,
        public string  $finalizeUrl,
        public string  $accountUrl,
        public ?string $certificateUrl,
    ) {}

    public static function fromResponse(Response $response, string $accountUrl = ''): OrderData
    {
        $url  = trim(rtrim($response->getHeaderLine('location') ?: $response->getRequestedUrl(), '?'));
        $body = $response->jsonBody();

        return new self(
            id: Url::extractId($url),
            url: $url,
            status: Arr::string($body, 'status'),
            expires: Arr::stringOrNull($body, 'expires'),
            identifiers: array_map(
                static fn(array $id): array => ['type' => Arr::string($id, 'type'), 'value' => Arr::string($id, 'value')],
                Arr::arrays($body, 'identifiers'),
            ),
            domainValidationUrls: Arr::strings($body, 'authorizations'),
            finalizeUrl: Arr::string($body, 'finalize'),
            accountUrl: $accountUrl,
            certificateUrl: Arr::stringOrNull($body, 'certificate'),
        );
    }

    public function isPending(): bool
    {
        return $this->status === 'pending';
    }

    public function isReady(): bool
    {
        return $this->status === 'ready';
    }

    public function isValid(): bool
    {
        return $this->status === 'valid';
    }

    public function isInvalid(): bool
    {
        return $this->status === 'invalid';
    }
}
