<?php

declare(strict_types=1);

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Support\Arr;

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
    /**
     * Record IDs created by deploy(), consumed by cleanup().
     *
     * A list per domain: a wildcard and its base name share one identifier and
     * therefore produce two TXT records under the same _acme-challenge name.
     *
     * @var array<string, list<string>> domain => record_ids
     */
    private array $recordIds = [];

    /** @var array<string, string> zone_name => zone_id */
    private array $zoneIdCache = [];

    private JsonHttpClient $httpClient;

    public function __construct(
        #[\SensitiveParameter]
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
        $this->maybePurgeExisting($domain);

        $zoneId   = $this->resolveZoneId($domain);
        $response = $this->httpClient->request('POST', "/zones/{$zoneId}/dns_records", [
            'type'    => 'TXT',
            'name'    => $this->challengeName($domain),
            'content' => $keyAuthorization,
            'ttl'     => 60, // Cloudflare's minimum outside Enterprise plans.
        ]);

        $recordId = Arr::id(Arr::array($response, 'result'), 'id');

        if ($recordId === null || $recordId === '') {
            throw new ChallengeException('Cloudflare did not return a record ID after creating the TXT record.');
        }

        $this->recordIds[$domain][] = $recordId;
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $recordIds = $this->recordIds[$domain] ?? [];

        if ($recordIds === []) {
            return;
        }

        $zoneId = $this->resolveZoneId($domain);

        foreach ($recordIds as $recordId) {
            $this->httpClient->request('DELETE', "/zones/{$zoneId}/dns_records/{$recordId}");
        }

        unset($this->recordIds[$domain]);
    }

    protected function deleteExistingRecords(string $domain): void
    {
        $zoneId   = $this->resolveZoneId($domain);
        $response = $this->httpClient->request('GET', "/zones/{$zoneId}/dns_records", queryParams: [
            'type' => 'TXT',
            'name' => $this->challengeName($domain),
        ]);

        foreach (Arr::arrays($response, 'result') as $record) {
            if (($recordId = Arr::id($record, 'id')) !== null) {
                $this->httpClient->request('DELETE', "/zones/{$zoneId}/dns_records/{$recordId}");
            }
        }
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
            $zoneId   = Arr::id(Arr::arrays($response, 'result')[0] ?? [], 'id');

            if ($zoneId !== null) {
                return $this->zoneIdCache[$candidate] = $zoneId;
            }
        }

        throw new ChallengeException(
            sprintf('No Cloudflare zone found for "%s". Verify the token has Zone:Read permission.', $domain),
        );
    }

}
