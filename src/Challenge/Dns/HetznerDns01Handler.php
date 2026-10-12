<?php

declare(strict_types=1);

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Exceptions\HttpChallengeException;
use CoyoteCert\Support\Arr;

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
     * Zone cache keyed by zone name and looked-up domain (auto-detect) or zone ID (explicit).
     *
     * @var array<string, array{id: string, name: string}>
     */
    private array $zoneCache = [];

    private JsonHttpClient $httpClient;

    public function __construct(
        #[\SensitiveParameter]
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

        $this->awaitAction($response, 'adding the TXT record');

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

        $this->awaitAction($response, 'removing the TXT records');
    }

    protected function deleteExistingRecords(string $domain): void
    {
        $zone     = $this->resolveZone($domain);
        $response = $this->request('GET', '/zones/' . $zone['id'] . '/rrsets', queryParams: [
            'name' => $this->rrName($domain, $zone['name']),
            'type' => 'TXT',
        ]);

        if (!empty($response['rrsets'])) {
            $this->awaitAction($this->request('DELETE', $this->rrsetPath($domain)), 'deleting the old TXT records');
        }
    }

    /**
     * @param array<string, mixed>|null $payload
     * @param array<string, mixed>|null $queryParams
     * @return array<mixed>
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

    /**
     * RRSet changes are asynchronous Cloud API actions: wait until one finishes, so the next
     * change to the same RRSet doesn't collide with it (423 locked) and a late failure is seen.
     *
     * @param array<mixed> $response
     */
    private function awaitAction(array $response, string $what): void
    {
        $action   = Arr::array($response, 'action');
        $deadline = time() + 60;

        while (Arr::stringOrNull($action, 'status') === 'running' && ($id = Arr::id($action, 'id')) !== null) {
            if (time() >= $deadline) {
                throw new ChallengeException(sprintf('Hetzner did not finish %s within 60 seconds.', $what));
            }

            sleep(1);
            $action = Arr::array($this->request('GET', '/zones/actions/' . $id), 'action');
        }

        if (Arr::stringOrNull($action, 'status') === 'error') {
            throw new ChallengeException(sprintf(
                'Hetzner failed %s: %s',
                $what,
                Arr::stringOrNull(Arr::array($action, 'error'), 'message') ?? 'unknown error',
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

            $zone = Arr::array($this->request('GET', '/zones/' . rawurlencode($this->zoneId)), 'zone');
            $id   = Arr::id($zone, 'id');
            $name = Arr::stringOrNull($zone, 'name');

            if ($id === null || $name === null || $name === '') {
                throw new ChallengeException(
                    sprintf('Hetzner zone "%s" not found or the token cannot read it.', $this->zoneId),
                );
            }

            return $this->zoneCache[$this->zoneId] = ['id' => $id, 'name' => $name];
        }

        // Cached per domain too, so sub.example.com doesn't re-query its non-zone candidates on every call
        $domain = strtolower($domain);

        if (isset($this->zoneCache[$domain])) {
            return $this->zoneCache[$domain];
        }

        foreach ($this->zoneCandidates($domain) as $candidate) {
            if (isset($this->zoneCache[$candidate])) {
                return $this->zoneCache[$domain] = $this->zoneCache[$candidate];
            }

            $response = $this->request('GET', '/zones', queryParams: ['name' => $candidate]);
            $id       = Arr::id(Arr::arrays($response, 'zones')[0] ?? [], 'id');

            if ($id !== null) {
                return $this->zoneCache[$domain] = $this->zoneCache[$candidate] = ['id' => $id, 'name' => $candidate];
            }
        }

        throw new ChallengeException(sprintf(
            'No Hetzner DNS zone found for "%s". Verify the zone exists in the Hetzner Console and the '
            . 'Cloud API token belongs to its project.',
            $domain,
        ));
    }
}
