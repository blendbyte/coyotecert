<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Exceptions\HttpChallengeException;

/**
 * DNS-01 challenge handler for the DigitalOcean DNS API.
 *
 * Creates and removes _acme-challenge TXT records via the DigitalOcean v2 REST API.
 * If $zone is omitted, the zone is resolved automatically by walking the domain's
 * public-suffix candidates (sub.example.com → example.com) and probing GET /domains.
 * Each candidate that returns HTTP 404 is skipped; the first 200 response wins.
 *
 * Usage:
 *
 *   new DigitalOceanDns01Handler(apiToken: 'your-api-token')
 *   new DigitalOceanDns01Handler(apiToken: 'your-api-token', zone: 'example.com')
 *   new DigitalOceanDns01Handler(apiToken: 'your-api-token')->propagationDelay(30)
 *   new DigitalOceanDns01Handler(apiToken: 'your-api-token')->skipPropagationCheck()
 */
class DigitalOceanDns01Handler extends AbstractDns01Handler
{
    /** @var array<string, string> domain => record_id, populated by deploy(), consumed by cleanup() */
    private array $recordIds = [];

    /** @var array<string, true> zone_name => true, caches confirmed zones */
    private array $zoneCache = [];

    private JsonHttpClient $httpClient;

    public function __construct(
        string $apiToken,
        private readonly ?string $zone = null,
        ?JsonHttpClient $httpClient = null,
    ) {
        $this->httpClient = $httpClient ?? new JsonHttpClient(
            baseUrl: 'https://api.digitalocean.com/v2',
            defaultHeaders: ['Authorization: Bearer ' . $apiToken],
            providerName: 'DigitalOcean',
        );
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $zone     = $this->resolveZone($domain);
        $response = $this->httpClient->request('POST', '/domains/' . $zone . '/records', [
            'type' => 'TXT',
            'name' => $this->relativeRecordName($domain, $zone),
            'data' => $keyAuthorization,
            'ttl'  => 30,
        ]);

        if (empty($response['domain_record']['id'])) {
            throw new ChallengeException('DigitalOcean did not return a record ID after creating the TXT record.');
        }

        $this->recordIds[$domain] = (string) $response['domain_record']['id'];
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $recordId = $this->recordIds[$domain] ?? null;

        if ($recordId === null) {
            return;
        }

        $zone = $this->resolveZone($domain);
        $this->httpClient->request('DELETE', '/domains/' . $zone . '/records/' . $recordId);
        unset($this->recordIds[$domain]);
    }

    private function resolveZone(string $domain): string
    {
        if ($this->zone !== null) {
            return $this->zone;
        }

        foreach ($this->zoneCandidates($domain) as $candidate) {
            if (isset($this->zoneCache[$candidate])) {
                return $candidate;
            }

            try {
                $this->httpClient->request('GET', '/domains/' . $candidate);
                $this->zoneCache[$candidate] = true;

                return $candidate;
            } catch (HttpChallengeException $e) {
                if ($e->httpStatus !== 404) {
                    throw $e; // 401, 403, 500, etc. — propagate; only 404 means "not found here"
                }
            }
        }

        throw new ChallengeException(
            sprintf('No DigitalOcean domain found for "%s". Verify the token has domain read access.', $domain),
        );
    }

}
