<?php

use CoyoteCert\Challenge\Dns\HetznerDns01Handler;
use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

class MockHetznerHandler extends HetznerDns01Handler
{
    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

/**
 * Build a handler + a trackable JsonHttpClient that replays $responses in order.
 *
 * @param list<array<string, mixed>|ChallengeException> $responses
 * @return array{JsonHttpClient&object, MockHetznerHandler}
 */
function hetznerHandler(string $token, ?string $zoneId, array $responses): array
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

    return [$client, new MockHetznerHandler($token, $zoneId, $client)];
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function hetznerZoneListResponse(string $id, string $name): array
{
    return ['zones' => [['id' => $id, 'name' => $name]]];
}

function hetznerZoneDetailsResponse(string $id, string $name): array
{
    return ['zone' => ['id' => $id, 'name' => $name]];
}

function hetznerRecordResponse(string $id): array
{
    return ['record' => ['id' => $id]];
}

// ── deploy() with explicit zone ID ────────────────────────────────────────────

it('deploy fetches zone details to resolve the zone name when zoneId is provided', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['method'])->toBe('GET');
    expect($client->captured[0]['path'])->toBe('/zones/zone-abc');
});

it('deploy caches zone details and does not re-fetch on subsequent calls', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-1'),
        hetznerRecordResponse('rec-2'),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $gets = array_filter($client->captured, fn($c) => $c['method'] === 'GET');
    expect(count($gets))->toBe(1);
});

it('deploy uses _acme-challenge as the record name for an apex domain', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[1]['payload']['name'])->toBe('_acme-challenge');
});

it('deploy uses _acme-challenge.sub as the record name for a subdomain', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[1]['payload']['name'])->toBe('_acme-challenge.sub');
});

it('deploy posts to /records with the correct full payload', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('example.com', '', 'my-key-auth');

    expect($client->captured[1]['method'])->toBe('POST');
    expect($client->captured[1]['path'])->toBe('/records');
    expect($client->captured[1]['payload'])->toBe([
        'type'    => 'TXT',
        'name'    => '_acme-challenge',
        'value'   => 'my-key-auth',
        'zone_id' => 'zone-abc',
        'ttl'     => 60,
    ]);
});

it('deploy stores the record ID for use in cleanup', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-xyz'),
        [],
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[2]['path'])->toContain('rec-xyz');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy auto-detects zone from apex domain', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        hetznerZoneListResponse('zone-1', 'example.com'),
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['method'])->toBe('GET');
    expect($client->captured[0]['path'])->toBe('/zones');
    expect($client->captured[0]['queryParams'])->toBe(['name' => 'example.com']);
});

it('deploy tries subdomain candidate first then falls back to apex', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        ['zones' => []],                                    // sub.example.com → not found
        hetznerZoneListResponse('zone-2', 'example.com'),   // example.com    → found
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams'])->toBe(['name' => 'sub.example.com']);
    expect($client->captured[1]['queryParams'])->toBe(['name' => 'example.com']);
});

it('deploy uses _acme-challenge.sub relative name when zone is auto-detected from apex', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        ['zones' => []],
        hetznerZoneListResponse('zone-2', 'example.com'),
        hetznerRecordResponse('rec-1'),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[2]['payload']['name'])->toBe('_acme-challenge.sub');
});

it('deploy caches zone and does not look it up a second time', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        hetznerZoneListResponse('zone-3', 'example.com'),
        hetznerRecordResponse('rec-a'),
        hetznerRecordResponse('rec-b'),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $gets = array_filter($client->captured, fn($c) => $c['method'] === 'GET');
    expect(count($gets))->toBe(1);
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy throws when the zone details response is empty', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        ['zone' => null],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'zone-abc');
});

it('deploy throws when no zone is found for the domain', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        ['zones' => []],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No Hetzner DNS zone found');
});

it('deploy throws when the API does not return a record ID', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        ['record' => null],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'did not return a record ID');
});

it('deploy propagates a ChallengeException thrown by the HTTP client', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        new ChallengeException('API returned HTTP 403 for GET /zones/zone-abc.'),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'HTTP 403');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup sends DELETE to /records/{id}', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-del'),
        [],
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[2]['method'])->toBe('DELETE');
    expect($client->captured[2]['path'])->toBe('/records/rec-del');
});

it('cleanup is a no-op when deploy was never called for the domain', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', []);

    expect(fn() => $handler->cleanup('example.com', ''))->not->toThrow(\Throwable::class);
    expect($client->captured)->toBeEmpty();
});

it('cleanup clears the stored record ID so a second call is a no-op', function () {
    [$client, $handler] = hetznerHandler('tok', 'zone-abc', [
        hetznerZoneDetailsResponse('zone-abc', 'example.com'),
        hetznerRecordResponse('rec-1'),
        [],
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second call: no extra request

    expect($client->captured)->toHaveCount(3);
});

// ── Default client wiring ─────────────────────────────────────────────────────

it('wires the default JsonHttpClient with the correct base URL and auth header', function () {
    $handler = new MockHetznerHandler('my-api-token');

    $clientProp = new ReflectionProperty(HetznerDns01Handler::class, 'httpClient');
    $client     = $clientProp->getValue($handler);

    $baseUrlProp = new ReflectionProperty(JsonHttpClient::class, 'baseUrl');
    $headersProp = new ReflectionProperty(JsonHttpClient::class, 'defaultHeaders');

    expect($baseUrlProp->getValue($client))->toBe('https://dns.hetzner.com/api/v1');
    expect($headersProp->getValue($client))->toContain('Auth-API-Token: my-api-token');
});
