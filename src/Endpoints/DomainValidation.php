<?php

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\DomainValidationData;
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
        $data = [];

        foreach ($orderData->domainValidationUrls as $domainValidationUrl) {
            $response = $this->client
                ->getHttpClient()
                ->post(
                    $domainValidationUrl,
                    $this->createKeyId($orderData->accountUrl, $domainValidationUrl)
                );

            if ($response->getHttpResponseCode() === 200) {
                $data[] = DomainValidationData::fromResponse($response);

                continue;
            }

            $this->logResponse('error', 'Cannot get domain validation', $response);
        }

        return $data;
    }

    /** @param DomainValidationData[] $challenges */
    public function getValidationData(array $challenges, ?AuthorizationChallengeEnum $authChallenge = null): array
    {
        $thumbprint = Thumbprint::make($this->getAccountPrivateKey());

        $authorizations = [];
        foreach ($challenges as $domainValidationData) {
            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::HTTP)
                && !empty($domainValidationData->file)
            ) {
                $authorizations[] = [
                    'identifier' => $domainValidationData->identifier['value'],
                    'type' => $domainValidationData->file['type'],
                    'filename' => $domainValidationData->file['token'],
                    'content' => $domainValidationData->file['token'].'.'.$thumbprint,
                ];
            }

            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::DNS)
                && !empty($domainValidationData->dns)
            ) {
                $authorizations[] = [
                    'identifier' => $domainValidationData->identifier['value'],
                    'type' => $domainValidationData->dns['type'],
                    'name' => '_acme-challenge',
                    'value' => DnsDigest::make($domainValidationData->dns['token'], $thumbprint),
                ];
            }

            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::DNS_PERSIST)
                && !empty($domainValidationData->dnsPersist)
            ) {
                $authorizations[] = [
                    'identifier' => $domainValidationData->identifier['value'],
                    'type' => $domainValidationData->dnsPersist['type'],
                    'name' => '_acme-challenge',
                    'value' => DnsDigest::make($domainValidationData->dnsPersist['token'], $thumbprint),
                ];
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
        $data = $this->createKeyId($accountData->url, $challengeData['url'], []);

        $response = $this->client->getHttpClient()->post($challengeData['url'], $data);

        if ($response->getHttpResponseCode() >= 400) {
            $this->logResponse(
                'error',
                $response->getBody()['detail'] ?? 'Unknown error',
                $response,
                ['data' => $data]
            );
        }

        return $response;
    }

    public function allChallengesPassed(OrderData $orderData): bool
    {
        $count = 0;
        while (($status = $this->status($orderData)) && $count < 4) {
            if ($this->challengeSucceeded($status)) {
                break;
            }

            if ($count === 3) {
                return false;
            }

            $this->client->logger('info', 'Challenge is not valid yet. Another attempt in 5 seconds.');

            sleep(5);

            $count++;
        }

        return true;
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
