<?php

use CoyoteCert\Challenge\Dns\ClouDnsDns01Handler;
use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

class MockClouDnsHandler extends ClouDnsDns01Handler
{
    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

/**
 * Build a handler + a trackable JsonHttpClient that replays $responses in order.
 *
 * @param list<array<string, mixed>|ChallengeException> $responses
 * @return array{JsonHttpClient&object, MockClouDnsHandler}
 */
function clouDnsHandler(string $authId, string $authPassword, ?string $zone, array $responses): array
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

    return [$client, new MockClouDnsHandler($authId, $authPassword, $zone, $client)];
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

function clouDnsRecordCreated(int $id): array
{
    return ['status' => 'Success', 'statusDescription' => 'The record was added successfully.', 'id' => $id];
}

function clouDnsDeleted(): array
{
    return ['status' => 'Success', 'statusDescription' => 'The record was deleted successfully.'];
}

// ── Auth params ───────────────────────────────────────────────────────────────

it('every request carries auth-id and auth-password as query params', function () {
    [$client, $handler] = clouDnsHandler('12345', 'secret', 'example.com', [
        clouDnsRecordCreated(1),
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
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(1);
    expect($client->captured[0]['path'])->toBe('/dns/add-record.json');
});

it('deploy uses _acme-challenge as the host for an apex domain', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams']['host'])->toBe('_acme-challenge');
});

it('deploy uses _acme-challenge.sub as the host for a subdomain', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams']['host'])->toBe('_acme-challenge.sub');
});

it('deploy sends all required fields to /dns/add-record.json', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(99),
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

it('deploy stores the record ID for use in cleanup', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(42),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[1]['queryParams']['record-id'])->toBe('42');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy queries /dns/get-zone-info.json to detect the zone', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsZoneFound('example.com'),
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['path'])->toBe('/dns/get-zone-info.json');
    expect($client->captured[0]['queryParams']['domain-name'])->toBe('example.com');
});

it('deploy skips candidates with a Failed response body and falls back to apex', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsZoneMissing(),                  // sub.example.com → not found (HTTP 200 + Failed)
        clouDnsZoneFound('example.com'),        // example.com    → found
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams']['domain-name'])->toBe('sub.example.com');
    expect($client->captured[1]['queryParams']['domain-name'])->toBe('example.com');
    expect($client->captured[2]['path'])->toBe('/dns/add-record.json');
});

it('deploy also skips candidates that return an HTTP error', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        new ChallengeException('API returned HTTP 400 for GET /dns/get-zone-info.json.'),
        clouDnsZoneFound('example.com'),
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[2]['path'])->toBe('/dns/add-record.json');
});

it('deploy uses _acme-challenge.sub when zone is auto-detected from apex', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsZoneMissing(),
        clouDnsZoneFound('example.com'),
        clouDnsRecordCreated(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[2]['queryParams']['host'])->toBe('_acme-challenge.sub');
});

it('deploy caches the detected zone and does not query it again', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsZoneFound('example.com'),
        clouDnsRecordCreated(1),
        clouDnsRecordCreated(2),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $zoneLookups = array_filter($client->captured, fn($c) => str_contains($c['path'], 'get-zone-info'));
    expect(count($zoneLookups))->toBe(1);
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy throws when no zone is found for any candidate', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', null, [
        clouDnsZoneMissing(),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No ClouDNS zone found');
});

it('deploy throws when the API does not return a record ID', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        ['status' => 'Failed', 'statusDescription' => 'Invalid record.'],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'did not return a record ID');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup sends a GET to /dns/delete-record.json with the correct params', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(77),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[1]['path'])->toBe('/dns/delete-record.json');
    expect($client->captured[1]['queryParams']['domain-name'])->toBe('example.com');
    expect($client->captured[1]['queryParams']['record-id'])->toBe('77');
});

it('cleanup is a no-op when deploy was never called for the domain', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', []);

    expect(fn() => $handler->cleanup('example.com', ''))->not->toThrow(\Throwable::class);
    expect($client->captured)->toBeEmpty();
});

it('cleanup clears the stored record ID so a second call is a no-op', function () {
    [$client, $handler] = clouDnsHandler('id', 'pw', 'example.com', [
        clouDnsRecordCreated(1),
        clouDnsDeleted(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second call: no extra request

    expect($client->captured)->toHaveCount(2);
});

// ── Default client wiring ─────────────────────────────────────────────────────

it('wires the default JsonHttpClient with the correct base URL', function () {
    $handler = new MockClouDnsHandler('12345', 'secret');

    $clientProp = new ReflectionProperty(ClouDnsDns01Handler::class, 'httpClient');
    $client     = $clientProp->getValue($handler);

    $baseUrlProp = new ReflectionProperty(JsonHttpClient::class, 'baseUrl');

    expect($baseUrlProp->getValue($client))->toBe('https://api.cloudns.net');
});
