<?php

use CoyoteCert\Challenge\Dns\HetznerDns01Handler;
use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

class MockHetznerHandler extends HetznerDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
    protected function deleteExistingRecords(string $domain): void {}
}

class PurgingHetznerHandler extends HetznerDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
}

/**
 * Build a handler + a trackable JsonHttpClient that replays $responses in order.
 *
 * @param list<array<string, mixed>|ChallengeException> $responses
 * @return array{JsonHttpClient&object, MockHetznerHandler}
 */
function hetznerHandler(string $token, ?string $zoneId, array $responses, bool $withPurge = false): array
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
        ? new PurgingHetznerHandler($token, $zoneId, $client)
        : new MockHetznerHandler($token, $zoneId, $client);

    return [$client, $handler];
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function hetznerZoneListResponse(int $id, string $name): array
{
    return ['zones' => [['id' => $id, 'name' => $name]]];
}

function hetznerZoneDetailsResponse(int $id, string $name): array
{
    return ['zone' => ['id' => $id, 'name' => $name]];
}

function hetznerActionResponse(string $status = 'running'): array
{
    return ['action' => ['id' => 1, 'command' => 'add_rrset_records', 'status' => $status]];
}

// ── deploy() with explicit zone ID ────────────────────────────────────────────

it('deploy fetches zone details to resolve the zone name when zoneId is provided', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        hetznerActionResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0])->toMatchArray(['method' => 'GET', 'path' => '/zones/42']);
});

it('deploy caches zone details and does not re-fetch on subsequent calls', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        hetznerActionResponse(),
        hetznerActionResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $gets = array_filter($client->captured, fn($c) => $c['method'] === 'GET');
    expect(count($gets))->toBe(1);
});

it('deploy adds the quoted value to the _acme-challenge TXT RRSet', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        hetznerActionResponse(),
    ]);

    $handler->deploy('example.com', '', 'my-key-auth');

    expect($client->captured[1]['method'])->toBe('POST');
    expect($client->captured[1]['path'])->toBe('/zones/42/rrsets/_acme-challenge/TXT/actions/add_records');
    expect($client->captured[1]['payload'])->toBe([
        'ttl'     => 60,
        'records' => [['value' => '"my-key-auth"', 'comment' => 'ACME challenge']],
    ]);
});

it('deploy uses a lower-case _acme-challenge.sub RRSet name for a subdomain', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        hetznerActionResponse(),
    ]);

    $handler->deploy('Sub.Example.com', '', 'keyauth');

    expect($client->captured[1]['path'])->toBe('/zones/42/rrsets/_acme-challenge.sub/TXT/actions/add_records');
});

it('deploy throws when the action fails immediately', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        ['action' => ['id' => 1, 'status' => 'error', 'error' => ['code' => 'x', 'message' => 'rrset is protected']]],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'rrset is protected');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy auto-detects zone from apex domain', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        hetznerZoneListResponse(7, 'example.com'),
        hetznerActionResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0])->toMatchArray([
        'method'      => 'GET',
        'path'        => '/zones',
        'queryParams' => ['name' => 'example.com'],
    ]);
    expect($client->captured[1]['path'])->toBe('/zones/7/rrsets/_acme-challenge/TXT/actions/add_records');
});

it('deploy tries subdomain candidate first then falls back to apex', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        ['zones' => []],                               // sub.example.com → not found
        hetznerZoneListResponse(8, 'example.com'),     // example.com    → found
        hetznerActionResponse(),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams'])->toBe(['name' => 'sub.example.com']);
    expect($client->captured[1]['queryParams'])->toBe(['name' => 'example.com']);
    expect($client->captured[2]['path'])->toBe('/zones/8/rrsets/_acme-challenge.sub/TXT/actions/add_records');
});

it('deploy caches zone and does not look it up a second time', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        hetznerZoneListResponse(9, 'example.com'),
        hetznerActionResponse(),
        hetznerActionResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $gets = array_filter($client->captured, fn($c) => $c['method'] === 'GET');
    expect(count($gets))->toBe(1);
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy throws when the zone details response is empty', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        ['zone' => null],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, '"42"');
});

it('deploy throws when no zone is found for the domain', function () {
    [$client, $handler] = hetznerHandler('tok', null, [
        ['zones' => []],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No Hetzner DNS zone found');
});

it('deploy propagates a ChallengeException thrown by the HTTP client', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        new ChallengeException('API returned HTTP 401 for GET /zones/42.'),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'HTTP 401');
});

it('deploy explains that a Cloud API token is needed when the API answers 401', function () {
    [$client, $handler] = hetznerHandler('old-dns-console-token', null, [
        new \CoyoteCert\Exceptions\HttpChallengeException('Hetzner: API returned HTTP 401 for GET /v1/zones.', 401),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(\CoyoteCert\Exceptions\HttpChallengeException::class, 'Use a Hetzner Cloud API token');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup is a no-op when deploy was never called for the domain', function () {
    [$client, $handler] = hetznerHandler('tok', '42', []);

    $handler->cleanup('example.com', '');

    expect($client->captured)->toBeEmpty();
});

it('cleanup removes every value deployed for the same domain (wildcard + base) in one call', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        hetznerActionResponse(),
        hetznerActionResponse(),
        hetznerActionResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth-base');
    $handler->deploy('example.com', '', 'keyauth-wildcard');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second identifier: already cleaned

    expect($client->captured)->toHaveCount(4);
    expect($client->captured[3])->toMatchArray([
        'method'  => 'POST',
        'path'    => '/zones/42/rrsets/_acme-challenge/TXT/actions/remove_records',
        'payload' => ['records' => [['value' => '"keyauth-base"'], ['value' => '"keyauth-wildcard"']]],
    ]);
});

it('cleanup throws when the remove action fails', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        hetznerActionResponse(),
        ['action' => ['id' => 2, 'status' => 'error', 'error' => ['message' => 'nope']]],
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect(fn() => $handler->cleanup('example.com', ''))->toThrow(ChallengeException::class, 'nope');
});

// ── Stale record purge ────────────────────────────────────────────────────────

it('deploy deletes an existing _acme-challenge TXT RRSet before adding the new value', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        ['rrsets' => [['id' => '_acme-challenge/TXT', 'name' => '_acme-challenge', 'type' => 'TXT']]],
        hetznerActionResponse(),               // DELETE rrset
        hetznerActionResponse(),               // add_records
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[1])->toMatchArray([
        'method'      => 'GET',
        'path'        => '/zones/42/rrsets',
        'queryParams' => ['name' => '_acme-challenge', 'type' => 'TXT'],
    ]);
    expect($client->captured[2])->toMatchArray(['method' => 'DELETE', 'path' => '/zones/42/rrsets/_acme-challenge/TXT']);
    expect($client->captured[3]['path'])->toEndWith('/actions/add_records');
});

it('deploy does not delete anything when no RRSet exists yet', function () {
    [$client, $handler] = hetznerHandler('tok', '42', [
        hetznerZoneDetailsResponse(42, 'example.com'),
        ['rrsets' => []],
        hetznerActionResponse(),
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(3);
    expect($client->captured[2]['path'])->toEndWith('/actions/add_records');
});

// ── Default client wiring ─────────────────────────────────────────────────────

it('wires the default JsonHttpClient with the Cloud API base URL and Bearer token', function () {
    $handler = new MockHetznerHandler('my-api-token');

    $clientProp = new ReflectionProperty(HetznerDns01Handler::class, 'httpClient');
    $client     = $clientProp->getValue($handler);

    $baseUrlProp = new ReflectionProperty(JsonHttpClient::class, 'baseUrl');
    $headersProp = new ReflectionProperty(JsonHttpClient::class, 'defaultHeaders');

    expect($baseUrlProp->getValue($client))->toBe('https://api.hetzner.cloud/v1');
    expect($headersProp->getValue($client))->toContain('Authorization: Bearer my-api-token');
});
