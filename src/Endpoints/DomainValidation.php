<?php

declare(strict_types=1);

namespace CoyoteCert\Endpoints;

use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\Dns01ValidationData;
use CoyoteCert\DTO\DomainValidationData;
use CoyoteCert\DTO\Http01ValidationData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\DTO\TlsAlpn01ValidationData;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\DomainValidationException;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;
use CoyoteCert\Support\DnsDigest;
use CoyoteCert\Support\JsonWebKey;
use CoyoteCert\Support\LocalChallengeTest;

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
     * @return array{0: DomainValidationData[], 1: ?int} [statuses, retryAfterSeconds|null]
     */
    private function statusWithRetryHint(OrderData $orderData): array
    {
        $data       = [];
        $retryAfter = null;

        foreach ($orderData->domainValidationUrls as $domainValidationUrl) {
            $response = $this->postSigned($domainValidationUrl, $orderData->accountUrl);

            // A missing authorization must not be skipped: an empty or partial list would
            // read as "every challenge passed" and leave a domain unvalidated.
            if ($response->getHttpResponseCode() !== 200) {
                $this->throwError($response, 'Cannot get domain validation.');
            }

            $data[] = DomainValidationData::fromResponse($response);

            $retryAfter ??= $this->parseRetryAfterSeconds($response);
        }

        return [$data, $retryAfter];
    }

    /**
     * @param DomainValidationData[] $challenges
     * @return array<int, Http01ValidationData|Dns01ValidationData|TlsAlpn01ValidationData>
     */
    public function getValidationData(array $challenges, ?AuthorizationChallengeEnum $authChallenge = null): array
    {
        $thumbprint = JsonWebKey::thumbprint(JsonWebKey::compute($this->getAccountPrivateKey()));

        $authorizations = [];
        foreach ($challenges as $domainValidationData) {
            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::HTTP)
                && !empty($domainValidationData->file)
            ) {
                $token            = $domainValidationData->file['token'];
                $keyAuth          = $token . '.' . $thumbprint;
                $authorizations[] = new Http01ValidationData(
                    identifier: $domainValidationData->identifier['value'],
                    filename: $token,
                    content: $keyAuth,
                    keyAuthorization: $keyAuth,
                );
            }

            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::DNS)
                && !empty($domainValidationData->dns)
            ) {
                $token            = $domainValidationData->dns['token'];
                $keyAuth          = $token . '.' . $thumbprint;
                $authorizations[] = new Dns01ValidationData(
                    identifier: $domainValidationData->identifier['value'],
                    name: '_acme-challenge',
                    value: DnsDigest::make($token, $thumbprint),
                    keyAuthorization: $keyAuth,
                );
            }

            if (
                (is_null($authChallenge) || $authChallenge === AuthorizationChallengeEnum::TLS_ALPN)
                && !empty($domainValidationData->tlsAlpn)
            ) {
                $token            = $domainValidationData->tlsAlpn['token'];
                $keyAuth          = $token . '.' . $thumbprint;
                $authorizations[] = new TlsAlpn01ValidationData(
                    identifier: $domainValidationData->identifier['value'],
                    token: $token,
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
        bool $localTest = true,
    ): Response {
        $this->client->logger('info', sprintf(
            'Start %s challenge for %s',
            $authChallenge->value,
            Arr::get($domainValidation->identifier, 'value', ''),
        ));

        $thumbprint = JsonWebKey::thumbprint(JsonWebKey::compute($this->getAccountPrivateKey()));

        $challengeData = $domainValidation->challengeData($authChallenge);

        if (empty($challengeData)) {
            throw new DomainValidationException(sprintf(
                'No %s challenge found for %s',
                $authChallenge->value,
                $domainValidation->identifier['value'],
            ));
        }

        $keyAuthorization = $challengeData['token'] . '.' . $thumbprint;

        if ($localTest && $authChallenge === AuthorizationChallengeEnum::HTTP) {
            LocalChallengeTest::http(
                $domainValidation->identifier['value'],
                $challengeData['token'],
                $keyAuthorization,
                $this->client->getHttpClient(),
            );
        }

        // RFC 8555 §7.5.1: challenge response payload must be an empty JSON object {}
        $response = $this->postSigned($challengeData['url'], $accountData->url, []);

        if ($response->getHttpResponseCode() >= 400) {
            $this->throwError($response, 'Challenge submission failed.');
        }

        return $response;
    }

    /** @throws \CoyoteCert\Exceptions\DomainValidationException immediately when the CA marks a challenge invalid; that status is terminal, so it's not worth burning the retry budget on. */
    public function allChallengesPassed(
        OrderData $orderData,
        int $maxAttempts = 10,
        ?AuthorizationChallengeEnum $challengeType = null,
    ): bool {
        // Debug-log what the authoritative nameservers serve while a dns-01 challenge is pending
        $logDns = $challengeType === AuthorizationChallengeEnum::DNS && $this->client->hasLogger();

        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            [$statuses, $retryAfter] = $this->statusWithRetryHint($orderData);

            if ($this->challengeSucceeded($statuses, $logDns)) {
                return true;
            }

            if ($attempt === $maxAttempts - 1) {
                break;
            }

            $delay = $this->pollDelay($retryAfter, $attempt, 5);
            $this->client->logger('info', "Challenge is not valid yet. Another attempt in {$delay} seconds.");
            sleep($delay);
        }

        return false;
    }

    /**
     * @param DomainValidationData[] $domainValidation
     * @throws \CoyoteCert\Exceptions\DomainValidationException
     */
    private function challengeSucceeded(array $domainValidation, bool $logDns = false): bool
    {
        foreach ($domainValidation as $status) {
            $this->client->logger(
                'info',
                "Check {$status->identifier['type']} challenge of {$status->identifier['value']}.",
            );

            if ($status->isInvalid()) {
                foreach ($status->getErrors() as $error) {
                    $this->client->logger('error', sprintf(
                        'Challenge for %s failed: %s (%s)',
                        $status->identifier['value'],
                        $error['error']['detail'] ?? 'no detail provided',
                        $error['error']['type']   ?? 'unknown error type',
                    ));
                }

                throw DomainValidationException::challengeInvalid($status->identifier['value'], $status->getErrors());
            }

            if ($logDns && !$status->isValid()) {
                foreach (LocalChallengeTest::lookupTxt($status->identifier['value']) as $result) {
                    $this->client->logger('debug', sprintf(
                        'DNS check via %s (%s) → _acme-challenge.%s TXT = %s%s',
                        $result['ns'],
                        $result['ip'],
                        $status->identifier['value'],
                        empty($result['found'])
                            ? '(none)'
                            : implode(', ', array_map(fn($v) => '"' . $v . '"', $result['found'])),
                        $result['ttl'] > 0 ? sprintf(' (ttl %ds)', $result['ttl']) : '',
                    ));
                }
            }

            if (!$status->isValid()) {
                return false;
            }
        }

        $this->client->logger('info', 'Challenge has been passed.');

        return true;
    }
}
