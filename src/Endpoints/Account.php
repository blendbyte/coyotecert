<?php

declare(strict_types=1);

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AccountNotFoundException;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Base64;
use CoyoteCert\Support\JsonWebKey;
use CoyoteCert\Support\JsonWebSignature;
use CoyoteCert\Support\KeyId;
use CoyoteCert\Support\OpenSsl;

class Account extends Endpoint
{
    public function exists(): bool
    {
        return $this->client->accountAdapter()->exists();
    }

    /**
     * Register an account. A new key is persisted only once the CA has accepted it, so a
     * failed registration never leaves an orphaned key behind. A key that is already stored
     * (e.g. orphaned by an older version) is registered as is.
     */
    public function create(string $email = ''): AccountData
    {
        $adapter    = $this->client->accountAdapter();
        $newKeyType = $adapter->exists() ? null : $this->client->getAccountKeyType();
        $accountKey = $newKeyType === null
            ? $adapter->getPrivateKey()
            : OpenSsl::openSslKeyToString(OpenSsl::generateKey($newKeyType));

        $payload = ['termsOfServiceAgreed' => true];

        if ($email !== '') {
            $payload['contact'] = ['mailto:' . $email];
        }

        // The directory says whether EAB is mandatory; the provider says whether it uses EAB at
        // all (e.g. configured credentials), so credentials are sent whenever either asks for them
        $provider = $this->client->getProvider();
        $required = (bool) ($this->client->directory()->meta()['externalAccountRequired'] ?? $provider->isEabRequired());
        $eab      = $required || $provider->isEabRequired() ? $provider->getEabCredentials($email) : null;

        if ($required && $eab === null) {
            throw new AcmeException(sprintf(
                '%s requires EAB credentials. Pass your EAB key ID and HMAC key when constructing the provider.',
                $provider->getDisplayName(),
            ));
        }

        if ($eab !== null) {
            $payload['externalAccountBinding'] = $this->buildEab(
                json_encode(JsonWebKey::compute($accountKey), JSON_THROW_ON_ERROR),
                $this->client->directory()->newAccount(),
                $eab,
            );
        }

        $response = $this->postToAccountUrl($payload, $accountKey);

        if ($response->getHttpResponseCode() === 201 && $response->hasHeader('location')) {
            if ($newKeyType !== null) {
                $adapter->savePrivateKey($accountKey, $newKeyType);
            }

            return AccountData::fromResponse($response);
        }

        $this->throwError($response, 'Creating account failed');
    }

    public function get(): AccountData
    {
        if (!$this->exists()) {
            throw new AcmeException('Local account keys not found.');
        }

        // Use the newAccountUrl to get the account data based on the key.
        // See https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1
        $payload  = ['onlyReturnExisting' => true];
        $response = $this->postToAccountUrl($payload);

        if ($response->getHttpResponseCode() === 200) {
            return AccountData::fromResponse($response);
        }

        if (($response->jsonBody()['type'] ?? '') === 'urn:ietf:params:acme:error:accountDoesNotExist') {
            $this->logResponse('error', 'Account does not exist for the stored key', $response);

            throw new AccountNotFoundException(
                $response->jsonBody()['detail'] ?? 'Account does not exist.',
                problemType: 'urn:ietf:params:acme:error:accountDoesNotExist',
            );
        }

        $this->throwError($response, 'Retrieving account failed');
    }

    /**
     * Update account contact information (RFC 8555 §7.3.2).
     *
     * @param string[] $contact Contact URIs, e.g. ['mailto:admin@example.com']
     */
    public function update(AccountData $account, array $contact): AccountData
    {
        $response = $this->postSigned($account->url, $account->url, ['contact' => $contact]);

        if ($response->getHttpResponseCode() === 200) {
            return AccountData::fromBody($account->url, $response->jsonBody());
        }

        $this->throwError($response, 'Updating account failed');
    }

    /**
     * Deactivate an account (RFC 8555 §7.3.6).
     * This is irreversible — a deactivated account cannot be reactivated.
     */
    public function deactivate(AccountData $account): AccountData
    {
        $response = $this->postSigned($account->url, $account->url, ['status' => 'deactivated']);

        if ($response->getHttpResponseCode() === 200) {
            return AccountData::fromBody($account->url, $response->jsonBody());
        }

        $this->throwError($response, 'Deactivating account failed');
    }

    /**
     * Roll over the account key (RFC 8555 §7.3.5).
     *
     * Generates a new key of the same type as the current account key,
     * sends a signed key-change request, and — on success — persists the
     * new key via the account interface so future requests use it.
     */
    public function keyRollover(AccountData $account): AccountData
    {
        $keyChangeUrl = $this->client->directory()->keyChange();
        $oldKeyPem    = $this->client->accountAdapter()->getPrivateKey();
        $oldJwk       = JsonWebKey::compute($oldKeyPem);

        // Detect current key type so the new key matches
        $existingKey = openssl_pkey_get_private($oldKeyPem);

        if ($existingKey === false) {
            throw new CryptoException('Cannot load account private key.');
        }

        $details = openssl_pkey_get_details($existingKey);

        if ($details === false) {
            throw new CryptoException('Failed to get key details.');
        }

        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            $keyType = match ($details['ec']['curve_name']) {
                'prime256v1' => KeyType::EC_P256,
                'secp384r1'  => KeyType::EC_P384,
                default      => KeyType::EC_P256,
            };
        } else {
            $keyType = $details['bits'] >= 4096 ? KeyType::RSA_4096 : KeyType::RSA_2048;
        }

        $newKeyPem = OpenSsl::openSslKeyToString(OpenSsl::generateKey($keyType));

        // The outer JWS is signed by the OLD key (KID), with the inner JWS as payload.
        // Both outer and inner must be rebuilt if we get a badNonce.
        $response = $this->client->getHttpClient()->post(
            $keyChangeUrl,
            $this->buildKeyChangeOuterJws($oldKeyPem, $newKeyPem, $oldJwk, $account->url, $keyChangeUrl),
        );
        $this->cacheResponseNonce($response);

        if ($this->isBadNonce($response)) {
            $response = $this->client->getHttpClient()->post(
                $keyChangeUrl,
                $this->buildKeyChangeOuterJws($oldKeyPem, $newKeyPem, $oldJwk, $account->url, $keyChangeUrl),
            );
            $this->cacheResponseNonce($response);
        }

        if ($response->getHttpResponseCode() === 200) {
            $this->client->accountAdapter()->savePrivateKey($newKeyPem, $keyType);

            // RFC 8555 §7.3.5 doesn't require an account object in the response (Pebble sends
            // none), so read the account back with the new key, which also confirms the change
            return $this->get();
        }

        $this->throwError($response, 'Key rollover failed');
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Build the outer JWS for a key-change request (RFC 8555 §7.3.5).
     *
     * The outer JWS is signed by the OLD account key (KID header) and wraps
     * the inner JWS (signed by the NEW key, JWK header) as its payload.
     *
     * @param array<string, string> $oldJwk
     * @return array<string, string>
     */
    private function buildKeyChangeOuterJws(
        string $oldKeyPem,
        string $newKeyPem,
        array  $oldJwk,
        string $accountUrl,
        string $keyChangeUrl,
    ): array {
        $innerJws = $this->buildKeyChangeInnerJws($newKeyPem, $oldJwk, $accountUrl, $keyChangeUrl);

        return KeyId::generate(
            $oldKeyPem,
            $accountUrl,
            $keyChangeUrl,
            $this->client->nonce()->getNew(),
            $innerJws,
        );
    }

    /** @return array<string, string> */
    private function buildEab(string $jwkJson, string $url, EabCredentials $eab): array
    {
        $protected64 = Base64::urlSafeEncode(json_encode([
            'alg' => $eab->algorithm->value,
            'kid' => $eab->kid,
            'url' => $url,
        ], JSON_THROW_ON_ERROR));

        $payload64 = Base64::urlSafeEncode($jwkJson);
        $hmacKey   = Base64::urlSafeDecode($eab->hmacKey);

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode(hash_hmac($eab->algorithm->hashAlgorithm(), $protected64 . '.' . $payload64, $hmacKey, true)),
        ];
    }

    /**
     * The inner JWS for key rollover (RFC 8555 §7.3.5): signed by the NEW key with a JWK
     * header and no nonce (the outer JWS carries it).
     *
     * @param array<string, string> $oldJwk
     * @return array<string, string>
     */
    private function buildKeyChangeInnerJws(
        string $newKeyPem,
        array  $oldJwk,
        string $accountUrl,
        string $keyChangeUrl,
    ): array {
        return JsonWebSignature::generate(['account' => $accountUrl, 'oldKey' => $oldJwk], $keyChangeUrl, null, $newKeyPem);
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, string>
     */
    private function signPayload(array $payload, string $accountKey): array
    {
        return JsonWebSignature::generate(
            $payload,
            $this->client->directory()->newAccount(),
            $this->client->nonce()->getNew(),
            $accountKey,
        );
    }

    /** @param array<string, mixed> $payload */
    private function postToAccountUrl(array $payload, ?string $accountKey = null): Response
    {
        $url = $this->client->directory()->newAccount();
        $accountKey ??= $this->client->accountAdapter()->getPrivateKey();
        $send = fn() => $this->client->getHttpClient()->post($url, $this->signPayload($payload, $accountKey));

        $response = $send();
        $this->cacheResponseNonce($response);

        if ($this->isBadNonce($response)) {
            $response = $send();
            $this->cacheResponseNonce($response);
        }

        return $response;
    }

}
