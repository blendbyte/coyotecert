<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\Dns01ValidationData;
use CoyoteCert\DTO\DomainValidationData;
use CoyoteCert\DTO\Http01ValidationData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\DomainValidationException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\DnsDigest;
use CoyoteCert\Support\JsonWebKey;
use CoyoteCert\Support\LocalChallengeTest;
use CoyoteCert\Support\Thumbprint;

class DomainValidation extends Endpoint
{
    /** @return DomainValidationData[] */
    public function status(OrderData $orderData): array
    {
        return $this->statusWithRetryHint($orderData)[0];
    }

    /**
     * Fetch all authz statuses and capture the first Retry-After hint.
     *
     * @return array{0: DomainValidationData[], 1: ?int}  [statuses, retryAfterSeconds|null]
     */
    private function statusWithRetryHint(OrderData $orderData): array
    {
        $data       = [];
        $retryAfter = null;

        foreach ($orderData->domainValidationUrls as $domainValidationUrl) {
            $response = $this->postSigned($domainValidationUrl, $orderData->accountUrl);

            if ($response->getHttpResponseCode() === 200) {
                $data[] = DomainValidationData::fromResponse($response);
            } else {
                $this->logResponse('error', 'Cannot get domain validation', $response);
            }

            $ra = (int) $response->getHeader('retry-after', 0);
            if ($ra > 0 && $retryAfter === null) {
                $retryAfter = $ra;
            }
        }

        return [$data, $retryAfter];
    }

    /**
     * @param DomainValidationData[] $challenges
     * @return array<int, Http01ValidationData|Dns01ValidationData>
     */
    public function getValidationData(array $challenges, ?AuthorizationChallengeEnum $authChallenge = null): array
    {
        $thumbprint = Thumbprint::make($this->getAccountPrivateKey());

        $authorizations = [];
        foreach ($challenges as $domainValidationData) {
            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::HTTP)
                && !empty($domainValidationData->file)
            ) {
                $token = $domainValidationData->file['token'];
                $keyAuth = $token . '.' . $thumbprint;
                $authorizations[] = new Http01ValidationData(
                    identifier:       $domainValidationData->identifier['value'],
                    filename:         $token,
                    content:          $keyAuth,
                    keyAuthorization: $keyAuth,
                );
            }

            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::DNS)
                && !empty($domainValidationData->dns)
            ) {
                $token   = $domainValidationData->dns['token'];
                $keyAuth = $token . '.' . $thumbprint;
                $authorizations[] = new Dns01ValidationData(
                    identifier:       $domainValidationData->identifier['value'],
                    name:             '_acme-challenge',
                    value:            DnsDigest::make($token, $thumbprint),
                    keyAuthorization: $keyAuth,
                );
            }

            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::DNS_PERSIST)
                && !empty($domainValidationData->dnsPersist)
            ) {
                $token   = $domainValidationData->dnsPersist['token'];
                $keyAuth = $token . '.' . $thumbprint;
                $authorizations[] = new Dns01ValidationData(
                    identifier:       $domainValidationData->identifier['value'],
                    name:             '_acme-challenge',
                    value:            DnsDigest::make($token, $thumbprint),
                    keyAuthorization: $keyAuth,
                );
            }
        }

        return $authorizations;
    }

    /** @throws \CoyoteCert\Exceptions\DomainValidationException */
    public function start(
        AccountData $accountData,
        DomainValidationData $domainValidation,
        AuthorizationChallengeEnum $authChallenge,
        bool $localTest = true
    ): Response {
        $this->client->logger('info', sprintf(
            'Start %s challenge for %s',
            $authChallenge->value,
            Arr::get($domainValidation->identifier, 'value', '')
        ));

        $thumbprint = JsonWebKey::thumbprint(JsonWebKey::compute($this->getAccountPrivateKey()));

        $challengeData = $domainValidation->challengeData($authChallenge);

        if (empty($challengeData)) {
            throw new DomainValidationException(sprintf(
                'No %s challenge found for %s',
                $authChallenge->value,
                $domainValidation->identifier['value']
            ));
        }

        $keyAuthorization = $challengeData['token'].'.'.$thumbprint;

        if ($localTest) {
            if ($authChallenge === AuthorizationChallengeEnum::HTTP) {
                LocalChallengeTest::http(
                    $domainValidation->identifier['value'],
                    $challengeData['token'],
                    $keyAuthorization,
                    $this->client->getHttpClient()
                );
            }

            if ($authChallenge === AuthorizationChallengeEnum::DNS || $authChallenge === AuthorizationChallengeEnum::DNS_PERSIST) {
                LocalChallengeTest::dns(
                    $domainValidation->identifier['value'],
                    '_acme-challenge',
                    DnsDigest::make($challengeData['token'], $thumbprint),
                );
            }
        }

        // RFC 8555 §7.5.1: challenge response payload must be an empty JSON object {}
        $response = $this->postSigned($challengeData['url'], $accountData->url, []);

        if ($response->getHttpResponseCode() >= 400) {
            $this->logResponse('error', $response->jsonBody()['detail'] ?? 'Unknown error', $response);
        }

        return $response;
    }

    public function allChallengesPassed(OrderData $orderData): bool
    {
        for ($attempt = 0; $attempt < 4; $attempt++) {
            [$statuses, $retryAfter] = $this->statusWithRetryHint($orderData);

            if ($this->challengeSucceeded($statuses)) {
                return true;
            }

            if ($attempt === 3) {
                break;
            }

            $delay = $retryAfter ?? min(5 * (2 ** $attempt), 64);
            $this->client->logger('info', "Challenge is not valid yet. Another attempt in {$delay} seconds.");
            sleep($delay);
        }

        return false;
    }

    /** @param DomainValidationData[] $domainValidation */
    private function challengeSucceeded(array $domainValidation): bool
    {
        // Verify if the challenges have been passed.
        foreach ($domainValidation as $status) {
            $this->client->logger(
                'info',
                "Check {$status->identifier['type']} challenge of {$status->identifier['value']}."
            );

            if (!$status->isValid()) {
                return false;
            }
        }

        $this->client->logger('info', 'Challenge has been passed.');

        return true;
    }
}
