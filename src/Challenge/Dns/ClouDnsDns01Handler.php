<?php

declare(strict_types=1);

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Support\Arr;

/**
 * DNS-01 challenge handler for the ClouDNS API.
 *
 * Creates and removes _acme-challenge TXT records via the ClouDNS REST API.
 * If $zone is omitted, the zone is resolved automatically by walking the domain's
 * public-suffix candidates (sub.example.com → example.com) and querying
 * /dns/get-zone-info.json. The ClouDNS API returns HTTP 200 with a Failed status
 * for non-existent zones, so zone detection checks the response body rather than
 * HTTP status codes.
 *
 * add-record.json does not return the new record's ID in its response body.
 * After creating the record, deploy() fetches /dns/records.json filtered by host
 * and type to locate the record and obtain its ID for use in cleanup().
 *
 * All operations use GET requests with credentials passed as query parameters:
 * the standard supported mode for the ClouDNS REST API.
 *
 * Usage:
 *
 *   new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret')
 *   new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret', zone: 'example.com')
 *   new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret')->propagationDelay(30)
 *   new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret')->skipPropagationCheck()
 */
class ClouDnsDns01Handler extends AbstractDns01Handler
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

    /** @var array<string, true> zone_name => true, caches confirmed zones */
    private array $zoneCache = [];

    private bool $authenticated = false;

    private JsonHttpClient $httpClient;

    public function __construct(
        private readonly string $authId,
        private readonly string $authPassword,
        private readonly ?string $zone = null,
        ?JsonHttpClient $httpClient = null,
    ) {
        $this->httpClient = $httpClient ?? new JsonHttpClient(
            baseUrl: 'https://api.cloudns.net',
            providerName: 'ClouDNS',
        );
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->maybePurgeExisting($domain);

        $zone = $this->resolveZone($domain);
        $host = $this->relativeRecordName($domain, $zone);

        $response = $this->httpClient->request('GET', '/dns/add-record.json', queryParams: [
            ...$this->auth(),
            'domain-name' => $zone,
            'record-type' => 'TXT',
            'host'        => $host,
            'record'      => $keyAuthorization,
            'ttl'         => 60, // Lowest TTL ClouDNS accepts.
        ]);

        if (($response['status'] ?? '') !== 'Success') {
            throw new ChallengeException(
                sprintf('ClouDNS add-record failed: %s', Arr::stringOrNull($response, 'statusDescription') ?? 'unknown error'),
            );
        }

        // add-record.json does not return the new record's ID.
        // Retrieve it via the records list, matching by TXT value.
        $records = $this->httpClient->request('GET', '/dns/records.json', queryParams: [
            ...$this->auth(),
            'domain-name' => $zone,
            'host'        => $host,
            'type'        => 'TXT',
        ]);

        $recordId = null;

        foreach ($records as $record) {
            if (is_array($record) && ($record['record'] ?? null) === $keyAuthorization) {
                $recordId = Arr::id($record, 'id');
                break;
            }
        }

        if ($recordId === null) {
            throw new ChallengeException('ClouDNS: could not locate the TXT record after creation.');
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

        $zone     = $this->resolveZone($domain);
        $failures = [];

        foreach ($recordIds as $recordId) {
            $response = $this->httpClient->request('GET', '/dns/delete-record.json', queryParams: [
                ...$this->auth(),
                'domain-name' => $zone,
                'record-id'   => $recordId,
            ]);

            // ClouDNS reports failures as HTTP 200 with a Failed status
            if (($response['status'] ?? '') !== 'Success') {
                $failures[] = sprintf('%s (%s)', $recordId, Arr::stringOrNull($response, 'statusDescription') ?? 'unknown error');
            }
        }

        unset($this->recordIds[$domain]);

        if ($failures !== []) {
            throw new ChallengeException('ClouDNS could not delete TXT record ' . implode(', ', $failures) . '.');
        }
    }

    protected function deleteExistingRecords(string $domain): void
    {
        $zone    = $this->resolveZone($domain);
        $host    = $this->relativeRecordName($domain, $zone);
        $records = $this->httpClient->request('GET', '/dns/records.json', queryParams: [
            ...$this->auth(),
            'domain-name' => $zone,
            'host'        => $host,
            'type'        => 'TXT',
        ]);

        foreach ($records as $record) {
            if (is_array($record) && ($recordId = Arr::id($record, 'id')) !== null) {
                $this->httpClient->request('GET', '/dns/delete-record.json', queryParams: [
                    ...$this->auth(),
                    'domain-name' => $zone,
                    'record-id'   => $recordId,
                ]);
            }
        }
    }

    private function resolveZone(string $domain): string
    {
        if ($this->zone !== null) {
            return $this->zone;
        }

        // A Failed zone lookup can't tell bad credentials from a missing zone, so check them first
        $this->assertAuthenticated();

        foreach ($this->zoneCandidates($domain) as $candidate) {
            if (isset($this->zoneCache[$candidate])) {
                return $candidate;
            }

            $response = $this->httpClient->request('GET', '/dns/get-zone-info.json', queryParams: [
                ...$this->auth(),
                'domain-name' => $candidate,
            ]);

            // ClouDNS returns HTTP 200 with {"status":"Failed"} for non-existent zones.
            if (!empty($response['name'])) {
                $this->zoneCache[$candidate] = true;

                return $candidate;
            }
        }

        throw new ChallengeException(
            sprintf('No ClouDNS zone found for "%s". Verify the credentials have zone access.', $domain),
        );
    }

    private function assertAuthenticated(): void
    {
        if ($this->authenticated) {
            return;
        }

        $response = $this->httpClient->request('GET', '/login/login.json', queryParams: $this->auth());

        if (($response['status'] ?? '') !== 'Success') {
            throw new ChallengeException(
                sprintf('ClouDNS login failed: %s', Arr::stringOrNull($response, 'statusDescription') ?? 'unknown error'),
            );
        }

        $this->authenticated = true;
    }

    /** @return array{auth-id: string, auth-password: string} */
    private function auth(): array
    {
        return ['auth-id' => $this->authId, 'auth-password' => $this->authPassword];
    }

}
