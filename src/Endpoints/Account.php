<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Exceptions\LetsEncryptClientException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Base64;
use CoyoteCert\Support\JsonWebKey;
use CoyoteCert\Support\JsonWebSignature;

class Account extends Endpoint
{
    public function exists(): bool
    {
        return $this->client->localAccount()->exists();
    }

    public function create(string $email = ''): AccountData
    {
        $this->client->localAccount()->generateNewKeys();

        $payload = ['termsOfServiceAgreed' => true];

        if ($this->client->getProvider()->isEabRequired()) {
            $eab = $this->client->getProvider()->getEabCredentials($email);

            if ($eab === null) {
                throw new LetsEncryptClientException(sprintf(
                    '%s requires EAB credentials. Pass your EAB key ID and HMAC key when constructing the provider.',
                    $this->client->getProvider()->getDisplayName()
                ));
            }

            $accountKey    = $this->client->localAccount()->getPrivateKey();
            $newAccountUrl = $this->client->directory()->newAccount();

            $payload['externalAccountBinding'] = $this->buildEab(
                json_encode(JsonWebKey::compute($accountKey), JSON_THROW_ON_ERROR),
                $newAccountUrl,
                $eab
            );
        }

        $response = $this->postToAccountUrl($payload);

        if ($response->getHttpResponseCode() === 201 && $response->hasHeader('location')) {
            return AccountData::fromResponse($response);
        }

        $this->throwError($response, 'Creating account failed');
    }

    public function get(): AccountData
    {
        if (!$this->exists()) {
            throw new LetsEncryptClientException('Local account keys not found.');
        }

        // Use the newAccountUrl to get the account data based on the key.
        // See https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1
        $payload = ['onlyReturnExisting' => true];
        $response = $this->postToAccountUrl($payload);

        if ($response->getHttpResponseCode() === 200) {
            return AccountData::fromResponse($response);
        }

        $this->throwError($response, 'Retrieving account failed');
    }

    private function buildEab(string $jwkJson, string $url, EabCredentials $eab): array
    {
        $protected64 = Base64::urlSafeEncode(json_encode([
            'alg' => 'HS256',
            'kid' => $eab->kid,
            'url' => $url,
        ], JSON_THROW_ON_ERROR));

        $payload64 = Base64::urlSafeEncode($jwkJson);
        $hmacKey   = Base64::urlSafeDecode($eab->hmacKey);

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode(hash_hmac('sha256', $protected64.'.'.$payload64, $hmacKey, true)),
        ];
    }

    private function signPayload(array $payload): array
    {
        return JsonWebSignature::generate(
            $payload,
            $this->client->directory()->newAccount(),
            $this->client->nonce()->getNew(),
            $this->client->localAccount()->getPrivateKey(),
        );
    }

    private function postToAccountUrl(array $payload): Response
    {
        return $this->client->getHttpClient()->post(
            $this->client->directory()->newAccount(),
            $this->signPayload($payload)
        );
    }

    protected function throwError(Response $response, string $defaultMessage): never
    {
        $message = $response->getBody()['detail'] ?? $defaultMessage;
        $this->logResponse('error', $message, $response);

        throw new LetsEncryptClientException($message);
    }
}
