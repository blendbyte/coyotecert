<?php

declare(strict_types=1);

use CoyoteCert\Challenge\Dns\CloudflareDns01Handler;
use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

// Disables the propagation DNS check so tests don't make real DNS queries.
class MockCloudflareHandler extends CloudflareDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
    protected function deleteExistingRecords(string $domain): void {}
}

class PurgingCloudflareHandler extends CloudflareDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
}

/**
 * Build a handler + a trackable JsonHttpClient that replays $responses in order.
 *
 * @param list<array<string, mixed>|ChallengeException> $responses
 * @return array{JsonHttpClient&object, MockCloudflareHandler}
 */
function cloudflareHandler(string $token, ?string $zoneId, array $responses, bool $withPurge = false): array
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
        ? new PurgingCloudflareHandler($token, $zoneId, $client)
        : new MockCloudflareHandler($token, $zoneId, $client);

    return [$client, $handler];
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function zoneResponse(string $id, string $name): array
{
    return ['result' => [['id' => $id, 'name' => $name]], 'success' => true];
}

function recordResponse(string $id): array
{
    return ['result' => ['id' => $id], 'success' => true];
}

function deleteResponse(): array
{
    return ['result' => ['id' => 'rec1'], 'success' => true];
}

// ── deploy() with explicit zone ID ────────────────────────────────────────────

it('deploy skips zone lookup when zoneId is provided', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [recordResponse('rec-1')]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(1);
    expect($client->captured[0]['method'])->toBe('POST');
    expect($client->captured[0]['path'])->toBe('/zones/zone-abc/dns_records');
    expect($client->captured[0]['payload'])->toBe([
        'type'    => 'TXT',
        'name'    => '_acme-challenge.example.com',
        'content' => 'keyauth',
        'ttl'     => 60,
    ]);
});

it('deploy stores the record ID returned by the API', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        recordResponse('rec-xyz'),
        deleteResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[1]['path'])->toContain('rec-xyz');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy auto-detects zone from apex domain', function () {
    [$client, $handler] = cloudflareHandler('tok', null, [
        zoneResponse('zone-1', 'example.com'),
        recordResponse('rec-1'),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['method'])->toBe('GET');
    expect($client->captured[0]['path'])->toBe('/zones');
    expect($client->captured[0]['queryParams'])->toBe(['name' => 'example.com']);
});

it('deploy tries subdomain candidate first then falls back to apex', function () {
    [$client, $handler] = cloudflareHandler('tok', null, [
        ['result' => [], 'success' => true],   // sub.example.com → not found
        zoneResponse('zone-2', 'example.com'),  // example.com    → found
        recordResponse('rec-2'),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['queryParams'])->toBe(['name' => 'sub.example.com']);
    expect($client->captured[1]['queryParams'])->toBe(['name' => 'example.com']);
    expect($client->captured[2]['method'])->toBe('POST');
});

it('deploy caches zone ID and does not look it up a second time', function () {
    [$client, $handler] = cloudflareHandler('tok', null, [
        zoneResponse('zone-3', 'example.com'),
        recordResponse('rec-a'),
        recordResponse('rec-b'),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $methods = array_column($client->captured, 'method');
    expect(array_count_values($methods)['GET'])->toBe(1);
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy throws when no zone is found for the domain', function () {
    [$client, $handler] = cloudflareHandler('tok', null, [
        ['result' => [], 'success' => true],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No Cloudflare zone found');
});

it('deploy throws when the API does not return a record ID', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        ['result' => null, 'success' => false],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'did not return a record ID');
});

it('deploy propagates a ChallengeException thrown by the HTTP client', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        new ChallengeException('API returned HTTP 403 for POST /zones/zone-abc/dns_records.'),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'HTTP 403');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup sends DELETE with the correct path', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        recordResponse('rec-del'),
        deleteResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[1]['method'])->toBe('DELETE');
    expect($client->captured[1]['path'])->toBe('/zones/zone-abc/dns_records/rec-del');
});

it('cleanup is a no-op when deploy was never called for the domain', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', []);

    expect(fn() => $handler->cleanup('example.com', ''))->not->toThrow(\Throwable::class);
    expect($client->captured)->toBeEmpty();
});

it('cleanup deletes every record deployed for the same domain (wildcard + base)', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        recordResponse('rec-base'),
        recordResponse('rec-wildcard'),
        deleteResponse(),
        deleteResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth-base');
    $handler->deploy('example.com', '', 'keyauth-wildcard');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second identifier: already cleaned

    expect($client->captured)->toHaveCount(4);
    expect($client->captured[2])->toMatchArray(['method' => 'DELETE', 'path' => '/zones/zone-abc/dns_records/rec-base']);
    expect($client->captured[3])->toMatchArray(['method' => 'DELETE', 'path' => '/zones/zone-abc/dns_records/rec-wildcard']);
});

it('cleanup clears the stored record ID so a second call is a no-op', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        recordResponse('rec-1'),
        deleteResponse(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second call: no extra request

    expect($client->captured)->toHaveCount(2);
});

// ── Stale record purge ────────────────────────────────────────────────────────

it('deploy deletes existing _acme-challenge TXT records before creating a new one', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        ['result' => [['id' => 'stale-1'], ['id' => 'stale-2']], 'success' => true], // list
        deleteResponse(),  // delete stale-1
        deleteResponse(),  // delete stale-2
        recordResponse('rec-new'),  // create
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0])->toMatchArray(['method' => 'GET', 'path' => '/zones/zone-abc/dns_records']);
    expect($client->captured[0]['queryParams'])->toBe(['type' => 'TXT', 'name' => '_acme-challenge.example.com']);
    expect($client->captured[1])->toMatchArray(['method' => 'DELETE', 'path' => '/zones/zone-abc/dns_records/stale-1']);
    expect($client->captured[2])->toMatchArray(['method' => 'DELETE', 'path' => '/zones/zone-abc/dns_records/stale-2']);
    expect($client->captured[3]['method'])->toBe('POST');
});

it('deploy skips purge when no existing records are found', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        ['result' => [], 'success' => true],  // empty list
        recordResponse('rec-new'),
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(2);
    expect($client->captured[0]['method'])->toBe('GET');
    expect($client->captured[1]['method'])->toBe('POST');
});

it('second deploy() for the same domain (wildcard + base) skips purge to preserve the first challenge', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        ['result' => [['id' => 'stale-1']], 'success' => true],  // list (first deploy only)
        deleteResponse(),                                          // delete stale-1
        recordResponse('rec-base'),                               // create base challenge
        recordResponse('rec-wildcard'),                           // create wildcard challenge (no list/delete)
    ], withPurge: true);

    $handler->deploy('example.com', '', 'keyauth-base');
    $handler->deploy('example.com', '', 'keyauth-wildcard');

    $methods = array_column($client->captured, 'method');
    expect(array_count_values($methods)['GET'])->toBe(1);   // only one list call
    expect(array_count_values($methods)['DELETE'])->toBe(1); // only one delete call
    expect(array_count_values($methods)['POST'])->toBe(2);   // two creates
});

it('keepExistingRecords() disables the pre-deploy purge', function () {
    [$client, $handler] = cloudflareHandler('tok', 'zone-abc', [
        recordResponse('rec-new'),
    ], withPurge: true);

    $handler->keepExistingRecords()->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(1);
    expect($client->captured[0]['method'])->toBe('POST');
});

// ── Default client wiring ─────────────────────────────────────────────────────

it('wires the default JsonHttpClient with the correct base URL and auth header', function () {
    $handler = new MockCloudflareHandler('my-api-token');

    $clientProp = new ReflectionProperty(CloudflareDns01Handler::class, 'httpClient');
    $client     = $clientProp->getValue($handler);

    $baseUrlProp = new ReflectionProperty(JsonHttpClient::class, 'baseUrl');
    $headersProp = new ReflectionProperty(JsonHttpClient::class, 'defaultHeaders');

    expect($baseUrlProp->getValue($client))->toBe('https://api.cloudflare.com/client/v4');
    expect($headersProp->getValue($client))->toContain('Authorization: Bearer my-api-token');
});
