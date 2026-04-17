<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\OrderNotFoundException;
use CoyoteCert\Support\Base64;

class Order extends Endpoint
{
    /**
     * @param string $replacesId ARI certId of the certificate being replaced (RFC 9773 §5).
     *                           Pass an empty string when issuing a brand-new certificate.
     */
    /**
     * @param string[] $domains
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

        if ($profile !== '' && $this->client->getProvider()->supportsProfiles()) {
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

        // If the `replaces` ARI hint was rejected, retry without it — the CA
        // may not recognise the issuer hash (e.g. Pebble with a self-signed CA).
        if ($replacesId !== '' && $response->getHttpResponseCode() === 400) {
            unset($payload['replaces']);
            $response = $this->postSigned($newOrderUrl, $accountData->url, $payload);

            if ($response->getHttpResponseCode() === 201) {
                return OrderData::fromResponse($response, $accountData->url);
            }
        }

        $this->throwError($response, 'Creating new order failed.', ['payload' => $payload]);
    }

    public function get(string $id): OrderData
    {
        $account = $this->client->account()->get();

        $orderUrl = sprintf(
            '%s%s/%s',
            $this->client->directory()->getOrder(),
            $account->id,
            $id,
        );

        // RFC 8555 §7.1.2.1: read-only resource access must use POST-as-GET.
        $response = $this->postSigned($orderUrl, $account->url);

        // Everything below 400 is a success.
        if ($response->getHttpResponseCode() < 400) {
            return OrderData::fromResponse($response, $account->url);
        }

        $this->logResponse('error', 'Getting order failed; bad response code.', $response);

        throw match ($response->getHttpResponseCode()) {
            404     => new OrderNotFoundException($response->jsonBody()['detail'] ?? 'Order cannot be found.'),
            default => $this->createException($response, 'Getting order failed.'),
        };
    }

    public function refresh(OrderData $order): OrderData
    {
        $response = $this->postSigned($order->url, $order->accountUrl);

        return OrderData::fromResponse($response, $order->accountUrl);
    }

    public function waitUntilValid(OrderData $order, int $maxAttempts = 10, int $sleepSeconds = 2): OrderData
    {
        for ($i = 0; $i < $maxAttempts; $i++) {
            $response = $this->postSigned($order->url, $order->accountUrl);
            $body     = $response->jsonBody();

            if (($body['status'] ?? '') === 'valid') {
                return OrderData::fromResponse($response, $order->accountUrl);
            }

            if (($body['status'] ?? '') === 'invalid') {
                throw new AcmeException('Order became invalid during finalization.');
            }

            sleep($this->retryAfterDelay($response, $i, $sleepSeconds));
        }

        throw new AcmeException("Order did not become valid after {$maxAttempts} attempts.");
    }

    public function finalize(OrderData $orderData, string $csr): bool
    {
        if (!$orderData->isReady()) {
            $this->client->logger(
                'error',
                "Order status for {$orderData->id} is {$orderData->status}. Cannot finalize order.",
            );

            return false;
        }

        if (preg_match('~-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----~s', $csr, $matches)) {
            $csr = $matches[1];
        }

        $csr = trim(Base64::urlSafeEncode(base64_decode($csr)));

        $response = $this->postSigned($orderData->finalizeUrl, $orderData->accountUrl, compact('csr'));

        if ($response->getHttpResponseCode() === 200) {
            return true;
        }

        $this->logResponse('error', 'Cannot finalize order ' . $orderData->id, $response, ['orderData' => $orderData]);

        return false;
    }
}
