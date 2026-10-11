<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Support\Base64;

class Order extends Endpoint
{
    /**
     * @param string[] $domains
     * @param string $replacesId ARI certId of the certificate being replaced (RFC 9773 §5).
     *                           Pass an empty string when issuing a brand-new certificate.
     */
    public function new(AccountData $accountData, array $domains, string $profile = '', string $replacesId = ''): OrderData
    {
        $identifiers = [];
        foreach ($domains as $domain) {
            $isIp = (bool) filter_var($domain, FILTER_VALIDATE_IP);

            if (!$isIp && preg_match_all('~(\*\.)~', $domain) > 1) {
                throw new AcmeException('Cannot create orders with multiple wildcards in one domain.');
            }

            $identifiers[] = [
                'type'  => $isIp ? 'ip' : 'dns',
                'value' => $domain,
            ];
        }

        $payload = ['identifiers' => $identifiers];

        if ($profile !== '') {
            $this->assertProfileOffered($profile);
            $payload['profile'] = $profile;
        }

        if ($replacesId !== '') {
            $payload['replaces'] = $replacesId;
        }

        $newOrderUrl = $this->client->directory()->newOrder();
        $response    = $this->postSigned($newOrderUrl, $accountData->url, $payload);

        if ($response->getHttpResponseCode() === 201) {
            return OrderData::fromResponse($response, $accountData->url);
        }

        // The `replaces` hint is only an optimisation: when the CA doesn't know the certificate
        // (malformed) or it was already replaced by an earlier, unfinished order (RFC 9773 §5,
        // alreadyReplaced), order without it. Other errors are about the order itself.
        $type = $response->jsonBody()['type'] ?? '';

        if ($replacesId !== '' && in_array($type, [
            'urn:ietf:params:acme:error:malformed',
            'urn:ietf:params:acme:error:alreadyReplaced',
        ], true)) {
            unset($payload['replaces']);
            $response = $this->postSigned($newOrderUrl, $accountData->url, $payload);

            if ($response->getHttpResponseCode() === 201) {
                return OrderData::fromResponse($response, $accountData->url);
            }
        }

        $this->throwError($response, 'Creating new order failed.', ['payload' => $payload]);
    }

    /**
     * A requested profile must be one the CA lists in its directory; without that list the
     * provider decides. Silently dropping it would issue a certificate of the wrong kind.
     */
    private function assertProfileOffered(string $profile): void
    {
        $offered  = $this->client->directory()->meta()['profiles'] ?? null;
        $provider = $this->client->getProvider();

        if (is_array($offered) && !array_key_exists($profile, $offered)) {
            throw new AcmeException(sprintf(
                '%s does not offer the "%s" profile. Available: %s.',
                $provider->getDisplayName(),
                $profile,
                implode(', ', array_keys($offered)),
            ));
        }

        if (!is_array($offered) && !$provider->supportsProfiles()) {
            throw new AcmeException(sprintf('%s does not support ACME profiles.', $provider->getDisplayName()));
        }
    }

    public function refresh(OrderData $order): OrderData
    {
        $response = $this->postSigned($order->url, $order->accountUrl);

        if ($response->getHttpResponseCode() !== 200) {
            $this->throwError($response, 'Cannot refresh order ' . $order->id);
        }

        return OrderData::fromResponse($response, $order->accountUrl);
    }

    public function waitUntilValid(OrderData $order, int $maxAttempts = 10, int $sleepSeconds = 2): OrderData
    {
        for ($i = 0; $i < $maxAttempts; $i++) {
            $response = $this->postSigned($order->url, $order->accountUrl);

            if ($response->getHttpResponseCode() !== 200) {
                $this->throwError($response, 'Cannot poll order ' . $order->id);
            }

            $body = $response->jsonBody();

            if (($body['status'] ?? '') === 'valid') {
                return OrderData::fromResponse($response, $order->accountUrl);
            }

            if (($body['status'] ?? '') === 'invalid') {
                $detail = $body['error']['detail'] ?? null;

                throw new AcmeException(
                    'Order became invalid during finalization' . ($detail !== null ? ": {$detail}" : '.'),
                    $body['error']['subproblems'] ?? [],
                );
            }

            if ($i < $maxAttempts - 1) {
                sleep($this->pollDelay($this->parseRetryAfterSeconds($response), $i, $sleepSeconds));
            }
        }

        throw new AcmeException("Order did not become valid after {$maxAttempts} attempts.");
    }

    public function finalize(OrderData $orderData, string $csr): void
    {
        if (!$orderData->isReady()) {
            throw new AcmeException(
                "Cannot finalize order {$orderData->id}: status is {$orderData->status}.",
            );
        }

        if (preg_match('~-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----~s', $csr, $matches)) {
            $csr = $matches[1];
        }

        $csr = trim(Base64::urlSafeEncode(base64_decode($csr)));

        $response = $this->postSigned($orderData->finalizeUrl, $orderData->accountUrl, compact('csr'));

        if ($response->getHttpResponseCode() !== 200) {
            $this->throwError($response, 'Cannot finalize order ' . $orderData->id);
        }
    }
}
