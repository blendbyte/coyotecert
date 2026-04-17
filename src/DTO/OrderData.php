<?php

namespace CoyoteCert\DTO;

use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\Url;

class OrderData
{
    /**
     * @param array<int, array<string, string>> $identifiers
     * @param string[] $domainValidationUrls
     */
    public function __construct(
        public readonly string  $id,
        public readonly string  $url,
        public readonly string  $status,
        public readonly string  $expires,
        public readonly array   $identifiers,
        public readonly array   $domainValidationUrls,
        public readonly string  $finalizeUrl,
        public readonly string  $accountUrl,
        public readonly ?string $certificateUrl,
        public readonly bool    $finalized = false,
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
            expires: $response->jsonBody()['expires'],
            identifiers: $response->jsonBody()['identifiers'],
            domainValidationUrls: $response->jsonBody()['authorizations'],
            finalizeUrl: $response->jsonBody()['finalize'],
            accountUrl: $accountUrl,
            certificateUrl: Arr::get($response->jsonBody(), 'certificate'),
        );
    }

    public function withCertificateUrl(string $url): self
    {
        return new self(
            id: $this->id,
            url: $this->url,
            status: $this->status,
            expires: $this->expires,
            identifiers: $this->identifiers,
            domainValidationUrls: $this->domainValidationUrls,
            finalizeUrl: $this->finalizeUrl,
            accountUrl: $this->accountUrl,
            certificateUrl: $url,
            finalized: true,
        );
    }

    public function withFinalized(bool $finalized): self
    {
        return new self(
            id: $this->id,
            url: $this->url,
            status: $this->status,
            expires: $this->expires,
            identifiers: $this->identifiers,
            domainValidationUrls: $this->domainValidationUrls,
            finalizeUrl: $this->finalizeUrl,
            accountUrl: $this->accountUrl,
            certificateUrl: $this->certificateUrl,
            finalized: $finalized,
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

    public function isFinalized(): bool
    {
        return ($this->finalized || $this->isValid());
    }

    public function isNotFinalized(): bool
    {
        return !$this->isFinalized();
    }
}
