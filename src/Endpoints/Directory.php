<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\Exceptions\LetsEncryptClientException;
use CoyoteCert\Http\Response;

class Directory extends Endpoint
{
    public function all(): Response
    {
        $response = $this->client
            ->getHttpClient()
            ->get($this->client->getProvider()->getDirectoryUrl());

        if ($response->getHttpResponseCode() >= 400) {
            $this->logResponse('error', 'Cannot get directory', $response);

            throw new LetsEncryptClientException('Cannot get directory');
        }

        return $response;
    }

    public function newNonce(): string
    {
        return $this->all()->getBody()['newNonce'];
    }

    public function newAccount(): string
    {
        return $this->all()->getBody()['newAccount'];
    }

    public function newOrder(): string
    {
        return $this->all()->getBody()['newOrder'];
    }

    public function getOrder(): string
    {
        $url = str_replace('new-order', 'order', $this->newOrder());

        return rtrim($url, '/') . '/';
    }

    public function revoke(): string
    {
        return $this->all()->getBody()['revokeCert'];
    }

    public function renewalInfo(): ?string
    {
        return $this->all()->getBody()['renewalInfo'] ?? null;
    }
}
