<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\EabCredentials;
use CoyoteCert\Enums\KeyType;
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

    public function create(string $email = ''): AccountData
    {
        $this->client->accountAdapter()->generateNewKeys();

        $payload = ['termsOfServiceAgreed' => true];

        if ($this->client->getProvider()->isEabRequired()) {
            $eab = $this->client->getProvider()->getEabCredentials($email);

            if ($eab === null) {
                throw new AcmeException(sprintf(
                    '%s requires EAB credentials. Pass your EAB key ID and HMAC key when constructing the provider.',
                    $this->client->getProvider()->getDisplayName(),
                ));
            }

            $accountKey    = $this->client->accountAdapter()->getPrivateKey();
            $newAccountUrl = $this->client->directory()->newAccount();

            $payload['externalAccountBinding'] = $this->buildEab(
                json_encode(JsonWebKey::compute($accountKey), JSON_THROW_ON_ERROR),
                $newAccountUrl,
                $eab,
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
            throw new AcmeException('Local account keys not found.');
        }

        // Use the newAccountUrl to get the account data based on the key.
        // See https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1
        $payload  = ['onlyReturnExisting' => true];
        $response = $this->postToAccountUrl($payload);

        if ($response->getHttpResponseCode() === 200) {
            return AccountData::fromResponse($response);
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

        if ($this->isBadNonce($response)) {
            $response = $this->client->getHttpClient()->post(
                $keyChangeUrl,
                $this->buildKeyChangeOuterJws($oldKeyPem, $newKeyPem, $oldJwk, $account->url, $keyChangeUrl),
            );
        }

        if ($response->getHttpResponseCode() === 200) {
            $this->client->accountAdapter()->savePrivateKey($newKeyPem, $keyType);

            return AccountData::fromBody($account->url, $response->jsonBody());
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
            'alg' => 'HS256',
            'kid' => $eab->kid,
            'url' => $url,
        ], JSON_THROW_ON_ERROR));

        $payload64 = Base64::urlSafeEncode($jwkJson);
        $hmacKey   = Base64::urlSafeDecode($eab->hmacKey);

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode(hash_hmac('sha256', $protected64 . '.' . $payload64, $hmacKey, true)),
        ];
    }

    /**
     * Build the inner JWS for key rollover (RFC 8555 §7.3.5).
     *
     * Signed by the NEW key with JWK header; no nonce (outer JWS carries it).
     */
    /**
     * @param array<string, string> $oldJwk
     * @return array<string, string>
     */
    private function buildKeyChangeInnerJws(
        string $newKeyPem,
        array  $oldJwk,
        string $accountUrl,
        string $keyChangeUrl,
    ): array {
        $privateKey = openssl_pkey_get_private($newKeyPem);

        if ($privateKey === false) {
            throw new CryptoException('Cannot load new private key.');
        }

        $details = openssl_pkey_get_details($privateKey);

        if ($details === false) {
            throw new CryptoException('Failed to get key details.');
        }

        $isEc = $details['type'] === OPENSSL_KEYTYPE_EC;

        if ($isEc) {
            [$alg, $digest, $sigLen] = match ($details['ec']['curve_name']) {
                'prime256v1' => ['ES256', 'SHA256', 32],
                'secp384r1'  => ['ES384', 'SHA384', 48],
                default      => throw new CryptoException("Unsupported EC curve: {$details['ec']['curve_name']}"),
            };
        } else {
            $alg    = 'RS256';
            $digest = 'SHA256';
            $sigLen = null;
        }

        $protected64 = Base64::urlSafeEncode(json_encode([
            'alg' => $alg,
            'jwk' => JsonWebKey::compute($newKeyPem),
            'url' => $keyChangeUrl,
        ], JSON_THROW_ON_ERROR));

        $payload64 = Base64::urlSafeEncode(json_encode([
            'account' => $accountUrl,
            'oldKey'  => $oldJwk,
        ], JSON_THROW_ON_ERROR));

        if (!openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, $digest)) {
            throw new CryptoException('Failed to sign key-change payload.');
        }

        if ($isEc) {
            $signed = JsonWebSignature::derToRaw($signed, $sigLen);
        }

        return [
            'protected' => $protected64,
            'payload'   => $payload64,
            'signature' => Base64::urlSafeEncode($signed),
        ];
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, string>
     */
    private function signPayload(array $payload): array
    {
        return JsonWebSignature::generate(
            $payload,
            $this->client->directory()->newAccount(),
            $this->client->nonce()->getNew(),
            $this->client->accountAdapter()->getPrivateKey(),
        );
    }

    /** @param array<string, mixed> $payload */
    private function postToAccountUrl(array $payload): Response
    {
        $url  = $this->client->directory()->newAccount();
        $send = fn() => $this->client->getHttpClient()->post($url, $this->signPayload($payload));

        $response = $send();

        if ($this->isBadNonce($response)) {
            $response = $send();
        }

        return $response;
    }

}
