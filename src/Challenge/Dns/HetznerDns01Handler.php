<?php

declare(strict_types=1);

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Exceptions\HttpChallengeException;

/**
 * DNS-01 challenge handler for Hetzner DNS via the Hetzner Cloud API.
 *
 * Adds and removes values in the _acme-challenge TXT RRSet through the Cloud API's
 * RRSet actions. Requires a Hetzner Cloud project API token with read & write access;
 * tokens from the retired DNS Console (dns.hetzner.com) do not work.
 *
 * If $zoneId is omitted the zone is resolved automatically by walking the domain's
 * public-suffix candidates (sub.example.com → example.com) and querying /zones.
 *
 * Usage:
 *
 *   new HetznerDns01Handler(apiToken: 'your-cloud-api-token')
 *   new HetznerDns01Handler(apiToken: 'your-cloud-api-token', zoneId: '12345')
 *   new HetznerDns01Handler(apiToken: 'your-cloud-api-token')->propagationDelay(30)
 *   new HetznerDns01Handler(apiToken: 'your-cloud-api-token')->skipPropagationCheck()
 */
class HetznerDns01Handler extends AbstractDns01Handler
{
    /**
     * TXT values added by deploy(), removed again by cleanup().
     *
     * A list per domain: a wildcard and its base name share one identifier and
     * therefore add two values to the same _acme-challenge RRSet.
     *
     * @var array<string, list<string>> domain => quoted TXT values
     */
    private array $values = [];

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
            baseUrl: 'https://api.hetzner.cloud/v1',
            defaultHeaders: ['Authorization: Bearer ' . $apiToken],
            providerName: 'Hetzner',
        );
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->maybePurgeExisting($domain);

        // The Cloud API stores TXT values in zone-file form, so the value is quoted
        $value    = '"' . $keyAuthorization . '"';
        $response = $this->request('POST', $this->rrsetPath($domain) . '/actions/add_records', [
            'ttl'     => 60, // Lowest TTL the Hetzner Cloud API accepts.
            'records' => [['value' => $value, 'comment' => 'ACME challenge']],
        ]);

        $this->assertActionSucceeded($response, 'adding the TXT record');

        $this->values[$domain][] = $value;
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $values = $this->values[$domain] ?? [];

        if ($values === []) {
            return;
        }

        $response = $this->request('POST', $this->rrsetPath($domain) . '/actions/remove_records', [
            'records' => array_map(static fn(string $value): array => ['value' => $value], $values),
        ]);

        unset($this->values[$domain]);

        $this->assertActionSucceeded($response, 'removing the TXT records');
    }

    protected function deleteExistingRecords(string $domain): void
    {
        $zone     = $this->resolveZone($domain);
        $response = $this->request('GET', '/zones/' . $zone['id'] . '/rrsets', queryParams: [
            'name' => $this->rrName($domain, $zone['name']),
            'type' => 'TXT',
        ]);

        if (!empty($response['rrsets'])) {
            $this->request('DELETE', $this->rrsetPath($domain));
        }
    }

    /**
     * @param array<string, mixed>|null $payload
     * @param array<string, mixed>|null $queryParams
     * @return array<string, mixed>
     */
    private function request(string $method, string $path, ?array $payload = null, ?array $queryParams = null): array
    {
        try {
            return $this->httpClient->request($method, $path, $payload, $queryParams);
        } catch (HttpChallengeException $e) {
            if ($e->httpStatus !== 401) {
                throw $e;
            }

            throw new HttpChallengeException(
                $e->getMessage() . ' Use a Hetzner Cloud API token (Hetzner Console > Security > API tokens); '
                . 'tokens from the old DNS Console no longer work.',
                401,
            );
        }
    }

    private function rrsetPath(string $domain): string
    {
        $zone = $this->resolveZone($domain);

        return sprintf('/zones/%s/rrsets/%s/TXT', $zone['id'], rawurlencode($this->rrName($domain, $zone['name'])));
    }

    /** RRSet names must be lower case and relative to the zone. */
    private function rrName(string $domain, string $zoneName): string
    {
        return strtolower($this->relativeRecordName($domain, $zoneName));
    }

    /** @param array<string, mixed> $response */
    private function assertActionSucceeded(array $response, string $what): void
    {
        if (($response['action']['status'] ?? null) === 'error') {
            throw new ChallengeException(sprintf(
                'Hetzner failed %s: %s',
                $what,
                $response['action']['error']['message'] ?? 'unknown error',
            ));
        }
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

            $response = $this->request('GET', '/zones/' . rawurlencode($this->zoneId));
            $zone     = $response['zone'] ?? null;

            if (empty($zone['id']) || empty($zone['name'])) {
                throw new ChallengeException(
                    sprintf('Hetzner zone "%s" not found or the token cannot read it.', $this->zoneId),
                );
            }

            $this->zoneCache[$this->zoneId] = ['id' => (string) $zone['id'], 'name' => $zone['name']];

            return $this->zoneCache[$this->zoneId];
        }

        foreach ($this->zoneCandidates(strtolower($domain)) as $candidate) {
            if (isset($this->zoneCache[$candidate])) {
                return $this->zoneCache[$candidate];
            }

            $response = $this->request('GET', '/zones', queryParams: ['name' => $candidate]);
            $zones    = $response['zones'] ?? [];

            if (!empty($zones[0]['id'])) {
                $this->zoneCache[$candidate] = ['id' => (string) $zones[0]['id'], 'name' => $candidate];

                return $this->zoneCache[$candidate];
            }
        }

        throw new ChallengeException(sprintf(
            'No Hetzner DNS zone found for "%s". Verify the zone exists in the Hetzner Console and the '
            . 'Cloud API token belongs to its project.',
            $domain,
        ));
    }
}
