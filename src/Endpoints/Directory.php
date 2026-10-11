<?php

declare(strict_types=1);

namespace CoyoteCert\Endpoints;

use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;

class Directory extends Endpoint
{
    /** Fetched once per Api instance: every signed request needs at least one directory URL. */
    private ?Response $response = null;

    public function all(): Response
    {
        if ($this->response !== null) {
            return $this->response;
        }

        $response = $this->client
            ->getHttpClient()
            ->get($this->client->getProvider()->getDirectoryUrl());

        if ($response->getHttpResponseCode() >= 400) {
            $this->logResponse('error', 'Cannot get directory', $response);

            throw new AcmeException('Cannot get directory');
        }

        return $this->response = $response;
    }

    /**
     * The directory's meta object (RFC 8555 §7.1.1): caaIdentities, profiles,
     * externalAccountRequired, termsOfService, website. Empty when the CA sends none.
     *
     * @return array<mixed>
     */
    public function meta(): array
    {
        return Arr::array($this->all()->jsonBody(), 'meta');
    }

    public function newNonce(): string
    {
        return Arr::string($this->all()->jsonBody(), 'newNonce');
    }

    public function newAccount(): string
    {
        return Arr::string($this->all()->jsonBody(), 'newAccount');
    }

    public function newOrder(): string
    {
        return Arr::string($this->all()->jsonBody(), 'newOrder');
    }

    public function revoke(): string
    {
        return Arr::string($this->all()->jsonBody(), 'revokeCert');
    }

    public function renewalInfo(): ?string
    {
        return Arr::stringOrNull($this->all()->jsonBody(), 'renewalInfo');
    }

    public function keyChange(): string
    {
        return Arr::string($this->all()->jsonBody(), 'keyChange');
    }
}
