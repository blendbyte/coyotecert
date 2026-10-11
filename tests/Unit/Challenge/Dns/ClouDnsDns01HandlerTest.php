<?php

declare(strict_types=1);

use CoyoteCert\Challenge\Dns\ClouDnsDns01Handler;
use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

class MockClouDnsHandler extends ClouDnsDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
    protected function deleteExistingRecords(string $domain): void {}
}

class PurgingClouDnsHandler extends ClouDnsDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
}

/**
 * Build a handler + a trackable JsonHttpClient that replays $responses in order.
 *
 * @param list<array<string, mixed>|ChallengeException> $responses
 * @return array{JsonHttpClient&object, MockClouDnsHandler}
 */
function clouDnsHandler(string $authId, string $authPassword, ?string $zone, array $responses, bool $withPurge = false): array
{
    $client = new class ($responses) extends JsonHttpClient {
        /** @var list<array{method: string, path: string, payload: mixed, queryParams: mixed}> */
        public array $captured = [];

        /** @var list<array<string, mixed>|ChallengeException> */
        private array $queue;

        /** @param list<array<string, mixed>|ChallengeException> $queue */
        public function __construct(array $queue)
        {
            parent::__construct('');
            $this->queue = $queue;
        }

        public function request(
            string $method,
            string $path,
            ?array $payload = null,
            ?array $queryParams = null,
            array $extraHeaders = [],
        ): array {
            $this->captured[] = compact('method', 'path', 'payload', 'queryParams');

            $response = array_shift($this->queue);

            if ($response === null) {
                throw new \RuntimeException("Unexpected API call: {$method} {$path}");
            }

            if ($response instanceof \Throwable) {
                throw $response;
            }

            return $response;
        }
    };

    $handler = $withPurge
        ? new PurgingClouDnsHandler($authId, $authPassword, $zone, $client)
        : new MockClouDnsHandler($authId, $authPassword, $zone, $client);

    return [$client, $handler];
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function clouDnsZoneFound(string $name): array
{
    return ['name' => $name, 'type' => 'master', 'status' => 1];
}

function clouDnsZoneMissing(): array
{
    // ClouDNS returns HTTP 200 with status Failed for non-existent zones.
    return ['status' => 'Failed', 'statusDescription' => "The zone doesn't exist."];
}

function clouDnsRecordCreated(): array
{
    // add-record.json returns only status; it does NOT return the new record's ID.
    return ['status' => 'Success', 'statusDescription' => 'The record was added successfully.'];
}

function clouDnsRecordsList(int $id, string $keyauth = 'keyauth'): array
{
    // records.json response is a JSON object keyed by record ID strings.
    return [(string) $id => ['id' => (string) $id, 'host' => '_acme-challenge', 'record' => $keyauth, 'type' => 'TXT']];
}

function clouDnsLoggedIn(): array
{
    return ['status' => 'Success', 'statusDescription' => 'Success authentication.'];
}

function clouDnsDeleted(): array
{
    return ['status' => 'Success', 'statusDescription' => 'The record was deleted successfully.'];
}

// ── Auth params ───────────────────────────────────────────────────────────────

it('every request carries auth-id and auth-password as query params', function () {
    [$client, $handler] = clouDnsHandler('12345', 'secret', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams'])->toMatchArray([
        'auth-id'       => '12345',
        'auth-password' => 'secret',
    ]);
});

// ── deploy() with explicit zone ───────────────────────────────────────────────

it('deploy skips zone detection when zone is provided', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(2);
    expect($client->captured[0]['path'])->toBe('/dns/add-record.json');
});

it('deploy uses _acme-challenge as the host for an apex domain', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams']['host'])->toBe('_acme-challenge');
});

it('deploy uses _acme-challenge.sub as the host for a subdomain', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams']['host'])->toBe('_acme-challenge.sub');
});

it('deploy sends all required fields to /dns/add-record.json', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(99, 'my-key-auth'),
    ]);

    $handler->deploy('example.com', '', 'my-key-auth');

    expect($client->captured[0]['path'])->toBe('/dns/add-record.json');
    expect($client->captured[0]['queryParams'])->toMatchArray([
        'domain-name' => 'example.com',
        'record-type' => 'TXT',
        'host'        => '_acme-challenge',
        'record'      => 'my-key-auth',
        'ttl'         => 60,
    ]);
});

it('deploy fetches records.json with domain-name host and type after add-record', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[1]['path'])->toBe('/dns/records.json');
    expect($client->captured[1]['queryParams'])->toMatchArray([
        'domain-name' => 'example.com',
        'host'        => '_acme-challenge',
        'type'        => 'TXT',
    ]);
});

it('deploy stores the record ID for use in cleanup', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(42),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[2]['queryParams']['record-id'])->toBe('42');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy checks the credentials, then queries /dns/get-zone-info.json to detect the zone', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsLoggedIn(),
        clouDnsZoneFound('example.com'),
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['path'])->toBe('/login/login.json');
    expect($client->captured[1]['path'])->toBe('/dns/get-zone-info.json');
    expect($client->captured[1]['queryParams']['domain-name'])->toBe('example.com');
});

it('deploy reports bad credentials instead of "zone not found"', function () {
    [$client, $handler] = clouDnsHandler('id', 'wrong', null, [
        ['status' => 'Failed', 'statusDescription' => 'Invalid authentication, incorrect auth-id or auth-password.'],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'ClouDNS login failed: Invalid authentication');
});

it('deploy skips candidates with a Failed response body and falls back to apex', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsLoggedIn(),
        clouDnsZoneMissing(),                  // sub.example.com → not found (HTTP 200 + Failed)
        clouDnsZoneFound('example.com'),        // example.com    → found
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[1]['queryParams']['domain-name'])->toBe('sub.example.com');
    expect($client->captured[2]['queryParams']['domain-name'])->toBe('example.com');
    expect($client->captured[3]['path'])->toBe('/dns/add-record.json');
    expect($client->captured[3]['queryParams']['host'])->toBe('_acme-challenge.sub');
});

it('deploy propagates HTTP errors during zone detection instead of skipping the candidate', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsLoggedIn(),
        new ChallengeException('ClouDNS: API returned HTTP 500 for GET /dns/get-zone-info.json.'),
    ]);

    expect(fn() => $handler->deploy('sub.example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'HTTP 500');
});

it('deploy checks credentials and caches the detected zone only once', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsLoggedIn(),
        clouDnsZoneFound('example.com'),
        clouDnsRecordCreated(),
        clouDnsRecordsList(1, 'keyauth1'),
        clouDnsRecordCreated(),
        clouDnsRecordsList(2, 'keyauth2'),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $lookups = array_filter($client->captured, fn($c) => str_contains($c['path'], 'get-zone-info') || str_contains($c['path'], 'login'));
    expect(count($lookups))->toBe(2);
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy throws when no zone is found for any candidate', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsLoggedIn(),
        clouDnsZoneMissing(),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No ClouDNS zone found');
});

it('deploy throws when add-record returns a Failed status', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        ['status' => 'Failed', 'statusDescription' => 'Invalid record.'],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'ClouDNS add-record failed');
});

it('deploy throws when the record cannot be found in the records list after creation', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        [],  // empty records list: record not found
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'could not locate the TXT record');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup sends a GET to /dns/delete-record.json with the correct params', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(77),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[2]['path'])->toBe('/dns/delete-record.json');
    expect($client->captured[2]['queryParams']['domain-name'])->toBe('example.com');
    expect($client->captured[2]['queryParams']['record-id'])->toBe('77');
});

it('cleanup reports records ClouDNS failed to delete, after trying all of them', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(11, 'a'),
        clouDnsRecordCreated(),
        clouDnsRecordsList(22, 'b'),
        ['status' => 'Failed', 'statusDescription' => 'Invalid record-id param.'],
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'a');
    $handler->deploy('example.com', '', 'b');

    expect(fn() => $handler->cleanup('example.com', ''))
        ->toThrow(ChallengeException::class, '11 (Invalid record-id param.)');
    expect($client->captured)->toHaveCount(6);
});

it('cleanup is a no-op when deploy was never called for the domain', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', []);

    expect(fn() => $handler->cleanup('example.com', ''))->not->toThrow(\Throwable::class);
    expect($client->captured)->toBeEmpty();
});

it('cleanup deletes every record deployed for the same domain (wildcard + base)', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(11, 'keyauth-base'),
        clouDnsRecordCreated(),
        clouDnsRecordsList(22, 'keyauth-wildcard'),
        clouDnsDeleted(),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth-base');
    $handler->deploy('example.com', '', 'keyauth-wildcard');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second identifier: already cleaned

    expect($client->captured)->toHaveCount(6);
    expect($client->captured[4]['queryParams']['record-id'])->toBe('11');
    expect($client->captured[5]['queryParams']['record-id'])->toBe('22');
});

it('cleanup clears the stored record ID so a second call is a no-op', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(),
        clouDnsRecordsList(1),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second call: no extra request

    expect($client->captured)->toHaveCount(3);
});

// ── Stale record purge ────────────────────────────────────────────────────────

it('deploy deletes existing _acme-challenge TXT records before creating a new one', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        [['id' => 'stale-1', 'record' => 'oldvalue']],  // records.json listing
        ['status' => 'Success'],                          // delete-record.json
        clouDnsRecordCreated(),                           // add-record.json
        [['id' => 'rec-new', 'record' => 'keyauth']],   // records.json (fetch ID)
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['path'])->toBe('/dns/records.json');
    expect($client->captured[0]['queryParams'])->toMatchArray(['host' => '_acme-challenge', 'type' => 'TXT']);
    expect($client->captured[1]['path'])->toBe('/dns/delete-record.json');
    expect($client->captured[1]['queryParams'])->toMatchArray(['record-id' => 'stale-1']);
    expect($client->captured[2]['path'])->toBe('/dns/add-record.json');
});

it('deploy does nothing when no existing records are found', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        [],                                             // empty list
        clouDnsRecordCreated(),                         // add-record.json
        [['id' => 'rec-new', 'record' => 'keyauth']], // records.json (fetch ID)
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['path'])->toBe('/dns/records.json');
    expect($client->captured[1]['path'])->toBe('/dns/add-record.json');
});

// ── Default client wiring ─────────────────────────────────────────────────────

it('wires the default JsonHttpClient with the correct base URL', function () {
    $handler = new MockClouDnsHandler('12345', 'secret');

    $clientProp = new ReflectionProperty(ClouDnsDns01Handler::class, 'httpClient');
    $client     = $clientProp->getValue($handler);

    $baseUrlProp = new ReflectionProperty(JsonHttpClient::class, 'baseUrl');

    expect($baseUrlProp->getValue($client))->toBe('https://api.cloudns.net');
});
