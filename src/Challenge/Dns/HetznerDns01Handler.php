<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

/**
 * DNS-01 challenge handler for the Hetzner DNS API.
 *
 * Creates and removes _acme-challenge TXT records via the Hetzner DNS v1 REST API.
 * If $zoneId is omitted the zone is resolved automatically by walking the domain's
 * public-suffix candidates (sub.example.com → example.com) and querying /zones.
 * When $zoneId is provided the zone name is fetched once from /zones/{id} so that
 * the TXT record name can be made relative to the zone (Hetzner requirement).
 *
 * Usage:
 *
 *   new HetznerDns01Handler(apiToken: 'your-api-token')
 *   new HetznerDns01Handler(apiToken: 'your-api-token', zoneId: 'abc123')
 *   new HetznerDns01Handler(apiToken: 'your-api-token')->propagationDelay(30)
 *   new HetznerDns01Handler(apiToken: 'your-api-token')->skipPropagationCheck()
 */
class HetznerDns01Handler extends AbstractDns01Handler
{
    /** @var array<string, string> domain => record_id, populated by deploy(), consumed by cleanup() */
    private array $recordIds = [];

    /**
     * Zone cache keyed by zone name (auto-detect) or zone ID (explicit).
     *
     * @var array<string, array{id: string, name: string}>
     */
    private array $zoneCache = [];

    private JsonHttpClient $httpClient;

    public function __construct(
        string $apiToken,
        private readonly ?string $zoneId = null,
        ?JsonHttpClient $httpClient = null,
    ) {
        $this->httpClient = $httpClient ?? new JsonHttpClient(
            baseUrl: 'https://dns.hetzner.com/api/v1',
            defaultHeaders: ['Auth-API-Token: ' . $apiToken],
            providerName: 'Hetzner',
        );
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $zone     = $this->resolveZone($domain);
        $response = $this->httpClient->request('POST', '/records', [
            'type'    => 'TXT',
            'name'    => $this->relativeRecordName($domain, $zone['name']),
            'value'   => $keyAuthorization,
            'zone_id' => $zone['id'],
            'ttl'     => 60,
        ]);

        if (empty($response['record']['id'])) {
            throw new ChallengeException('Hetzner did not return a record ID after creating the TXT record.');
        }

        $this->recordIds[$domain] = $response['record']['id'];
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $recordId = $this->recordIds[$domain] ?? null;

        if ($recordId === null) {
            return;
        }

        $this->httpClient->request('DELETE', '/records/' . $recordId);
        unset($this->recordIds[$domain]);
    }

    /**
     * @return array{id: string, name: string}
     */
    private function resolveZone(string $domain): array
    {
        if ($this->zoneId !== null) {
            if (isset($this->zoneCache[$this->zoneId])) {
                return $this->zoneCache[$this->zoneId];
            }

            $response = $this->httpClient->request('GET', '/zones/' . $this->zoneId);
            $zone     = $response['zone'] ?? null;

            if (empty($zone['id']) || empty($zone['name'])) {
                throw new ChallengeException(
                    sprintf('Hetzner zone "%s" not found or token lacks DNS:Read permission.', $this->zoneId),
                );
            }

            $this->zoneCache[$this->zoneId] = ['id' => $zone['id'], 'name' => $zone['name']];

            return $this->zoneCache[$this->zoneId];
        }

        foreach ($this->zoneCandidates($domain) as $candidate) {
            if (isset($this->zoneCache[$candidate])) {
                return $this->zoneCache[$candidate];
            }

            $response = $this->httpClient->request('GET', '/zones', queryParams: ['name' => $candidate]);
            $zones    = $response['zones'] ?? [];

            if (!empty($zones)) {
                $this->zoneCache[$candidate] = ['id' => $zones[0]['id'], 'name' => $candidate];

                return $this->zoneCache[$candidate];
            }
        }

        throw new ChallengeException(
            sprintf('No Hetzner DNS zone found for "%s". Verify the token has DNS:Read permission.', $domain),
        );
    }

}
