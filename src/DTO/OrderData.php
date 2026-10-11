<?php

namespace CoyoteCert\DTO;

use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\Url;

readonly class OrderData
{
    /**
     * @param array<int, array<string, string>> $identifiers
     * @param string[] $domainValidationUrls
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
        $url = $response->getHeader('location');

        if (empty($url)) {
            $url = $response->getRequestedUrl();
        }

        $url = trim(rtrim($url, '?'));

        return new self(
            id: Url::extractId($url),
            url: $url,
            status: $response->jsonBody()['status'],
            expires: $response->jsonBody()['expires'] ?? null,
            identifiers: $response->jsonBody()['identifiers'],
            domainValidationUrls: $response->jsonBody()['authorizations'],
            finalizeUrl: $response->jsonBody()['finalize'],
            accountUrl: $accountUrl,
            certificateUrl: Arr::get($response->jsonBody(), 'certificate'),
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
