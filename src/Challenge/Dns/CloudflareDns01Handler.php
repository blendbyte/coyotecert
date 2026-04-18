<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

/**
 * DNS-01 challenge handler for the Cloudflare API.
 *
 * Creates and removes _acme-challenge TXT records via the Cloudflare v4 REST API.
 * If $zoneId is omitted, the zone is resolved automatically by walking the domain's
 * public-suffix candidates (sub.example.com → example.com) and querying /zones.
 *
 * Usage:
 *
 *   new CloudflareDns01Handler(apiToken: 'your-api-token')
 *   new CloudflareDns01Handler(apiToken: 'your-api-token', zoneId: 'abc123')
 *   new CloudflareDns01Handler(apiToken: 'your-api-token')->propagationDelay(30)
 *   new CloudflareDns01Handler(apiToken: 'your-api-token')->skipPropagationCheck()
 */
class CloudflareDns01Handler extends AbstractDns01Handler
{
    /** @var array<string, string> domain => record_id, populated by deploy(), consumed by cleanup() */
    private array $recordIds = [];

    /** @var array<string, string> zone_name => zone_id */
    private array $zoneIdCache = [];

    private JsonHttpClient $httpClient;

    public function __construct(
        string $apiToken,
        private readonly ?string $zoneId = null,
        ?JsonHttpClient $httpClient = null,
    ) {
        $this->httpClient = $httpClient ?? new JsonHttpClient(
            baseUrl: 'https://api.cloudflare.com/client/v4',
            defaultHeaders: ['Authorization: Bearer ' . $apiToken],
            providerName: 'Cloudflare',
        );
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $zoneId   = $this->resolveZoneId($domain);
        $response = $this->httpClient->request('POST', "/zones/{$zoneId}/dns_records", [
            'type'    => 'TXT',
            'name'    => $this->challengeName($domain),
            'content' => $keyAuthorization,
            'ttl'     => 60,
        ]);

        if (empty($response['result']['id'])) {
            throw new ChallengeException('Cloudflare did not return a record ID after creating the TXT record.');
        }

        $this->recordIds[$domain] = $response['result']['id'];
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $recordId = $this->recordIds[$domain] ?? null;

        if ($recordId === null) {
            return;
        }

        $zoneId = $this->resolveZoneId($domain);
        $this->httpClient->request('DELETE', "/zones/{$zoneId}/dns_records/{$recordId}");
        unset($this->recordIds[$domain]);
    }

    private function resolveZoneId(string $domain): string
    {
        if ($this->zoneId !== null) {
            return $this->zoneId;
        }

        foreach ($this->zoneCandidates($domain) as $candidate) {
            if (isset($this->zoneIdCache[$candidate])) {
                return $this->zoneIdCache[$candidate];
            }

            $response = $this->httpClient->request('GET', '/zones', queryParams: ['name' => $candidate]);
            $zones    = $response['result'] ?? [];

            if (!empty($zones)) {
                $this->zoneIdCache[$candidate] = $zones[0]['id'];

                return $this->zoneIdCache[$candidate];
            }
        }

        throw new ChallengeException(
            sprintf('No Cloudflare zone found for "%s". Verify the token has Zone:Read permission.', $domain),
        );
    }

}
