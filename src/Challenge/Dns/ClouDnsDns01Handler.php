<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

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
 * All operations use GET requests with credentials passed as query parameters —
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
    /** @var array<string, string> domain => record_id, populated by deploy(), consumed by cleanup() */
    private array $recordIds = [];

    /** @var array<string, true> zone_name => true, caches confirmed zones */
    private array $zoneCache = [];

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
        $zone = $this->resolveZone($domain);
        $host = $this->relativeRecordName($domain, $zone);

        $response = $this->httpClient->request('GET', '/dns/add-record.json', queryParams: [
            ...$this->auth(),
            'domain-name' => $zone,
            'record-type' => 'TXT',
            'host'        => $host,
            'record'      => $keyAuthorization,
            'ttl'         => 60,
        ]);

        if (($response['status'] ?? '') !== 'Success') {
            throw new ChallengeException(
                sprintf('ClouDNS add-record failed: %s', $response['statusDescription'] ?? 'unknown error'),
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
                $recordId = (string) $record['id'];
                break;
            }
        }

        if ($recordId === null) {
            throw new ChallengeException('ClouDNS: could not locate the TXT record after creation.');
        }

        $this->recordIds[$domain] = $recordId;
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $recordId = $this->recordIds[$domain] ?? null;

        if ($recordId === null) {
            return;
        }

        $zone = $this->resolveZone($domain);
        $this->httpClient->request('GET', '/dns/delete-record.json', queryParams: [
            ...$this->auth(),
            'domain-name' => $zone,
            'record-id'   => $recordId,
        ]);
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
                $response = $this->httpClient->request('GET', '/dns/get-zone-info.json', queryParams: [
                    ...$this->auth(),
                    'domain-name' => $candidate,
                ]);
            } catch (ChallengeException) {
                continue;
            }

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

    /** @return array{auth-id: string, auth-password: string} */
    private function auth(): array
    {
        return ['auth-id' => $this->authId, 'auth-password' => $this->authPassword];
    }

}
