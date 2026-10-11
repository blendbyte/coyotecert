<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Response;

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
     * @return array<string, mixed>
     */
    public function meta(): array
    {
        $meta = $this->all()->jsonBody()['meta'] ?? [];

        return is_array($meta) ? $meta : [];
    }

    public function newNonce(): string
    {
        return $this->all()->jsonBody()['newNonce'];
    }

    public function newAccount(): string
    {
        return $this->all()->jsonBody()['newAccount'];
    }

    public function newOrder(): string
    {
        return $this->all()->jsonBody()['newOrder'];
    }

    public function revoke(): string
    {
        return $this->all()->jsonBody()['revokeCert'];
    }

    public function renewalInfo(): ?string
    {
        return $this->all()->jsonBody()['renewalInfo'] ?? null;
    }

    public function keyChange(): string
    {
        return $this->all()->jsonBody()['keyChange'];
    }
}
