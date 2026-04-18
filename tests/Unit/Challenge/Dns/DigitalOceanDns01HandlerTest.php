<?php

use CoyoteCert\Challenge\Dns\DigitalOceanDns01Handler;
use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Exceptions\HttpChallengeException;

class MockDigitalOceanHandler extends DigitalOceanDns01Handler
{
    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

/**
 * Build a handler + a trackable JsonHttpClient that replays $responses in order.
 *
 * @param list<array<string, mixed>|ChallengeException> $responses
 * @return array{JsonHttpClient&object, MockDigitalOceanHandler}
 */
function doHandler(string $token, ?string $zone, array $responses): array
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

    return [$client, new MockDigitalOceanHandler($token, $zone, $client)];
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function doZoneResponse(string $name): array
{
    return ['domain' => ['name' => $name, 'ttl' => 30]];
}

function doZoneNotFound(string $candidate): HttpChallengeException
{
    return new HttpChallengeException("API returned HTTP 404 for GET /domains/{$candidate}.", 404);
}

function doRecordResponse(int $id): array
{
    return ['domain_record' => ['id' => $id, 'type' => 'TXT']];
}

// ── deploy() with explicit zone ───────────────────────────────────────────────

it('deploy skips zone detection when zone is provided', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [doRecordResponse(1)]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured)->toHaveCount(1);
    expect($client->captured[0]['method'])->toBe('POST');
});

it('deploy uses _acme-challenge as the record name for an apex domain', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [doRecordResponse(1)]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['payload']['name'])->toBe('_acme-challenge');
});

it('deploy uses _acme-challenge.sub as the record name for a subdomain', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [doRecordResponse(1)]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['payload']['name'])->toBe('_acme-challenge.sub');
});

it('deploy posts to /domains/{zone}/records with the correct payload', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [doRecordResponse(99)]);

    $handler->deploy('example.com', '', 'my-key-auth');

    expect($client->captured[0]['method'])->toBe('POST');
    expect($client->captured[0]['path'])->toBe('/domains/example.com/records');
    expect($client->captured[0]['payload'])->toBe([
        'type' => 'TXT',
        'name' => '_acme-challenge',
        'data' => 'my-key-auth',
        'ttl'  => 30,
    ]);
});

it('deploy casts the integer record ID to a string for storage', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [
        doRecordResponse(12345),
        [],
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[1]['path'])->toContain('12345');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy probes GET /domains/{name} to detect the zone', function () {
    [$client, $handler] = doHandler('tok', null, [
        doZoneResponse('example.com'),
        doRecordResponse(1),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($client->captured[0]['method'])->toBe('GET');
    expect($client->captured[0]['path'])->toBe('/domains/example.com');
});

it('deploy skips candidates that return HTTP 404 and falls back to apex', function () {
    [$client, $handler] = doHandler('tok', null, [
        doZoneNotFound('sub.example.com'),   // 404 → try next
        doZoneResponse('example.com'),        // 200 → zone found
        doRecordResponse(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[0]['path'])->toBe('/domains/sub.example.com');
    expect($client->captured[1]['path'])->toBe('/domains/example.com');
    expect($client->captured[2]['method'])->toBe('POST');
});

it('deploy uses _acme-challenge.sub when zone is auto-detected from apex', function () {
    [$client, $handler] = doHandler('tok', null, [
        doZoneNotFound('sub.example.com'),
        doZoneResponse('example.com'),
        doRecordResponse(1),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($client->captured[2]['payload']['name'])->toBe('_acme-challenge.sub');
});

it('deploy caches the detected zone and does not probe again on second deploy', function () {
    [$client, $handler] = doHandler('tok', null, [
        doZoneResponse('example.com'),
        doRecordResponse(1),
        doRecordResponse(2),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $gets = array_filter($client->captured, fn($c) => $c['method'] === 'GET');
    expect(count($gets))->toBe(1);
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy propagates non-404 HTTP errors during zone detection', function () {
    [$client, $handler] = doHandler('tok', null, [
        new HttpChallengeException('DigitalOcean: API returned HTTP 401 for GET /domains/example.com.', 401),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(HttpChallengeException::class, 'HTTP 401');
});

it('deploy throws when no domain is found for any candidate', function () {
    [$client, $handler] = doHandler('tok', null, [
        doZoneNotFound('example.com'),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No DigitalOcean domain found');
});

it('deploy throws when the API does not return a record ID', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [
        ['domain_record' => null],
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'did not return a record ID');
});

it('deploy propagates a ChallengeException from the record creation call', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [
        new ChallengeException('API returned HTTP 422 for POST /domains/example.com/records.'),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'HTTP 422');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup sends DELETE to /domains/{zone}/records/{id}', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [
        doRecordResponse(77),
        [],
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($client->captured[1]['method'])->toBe('DELETE');
    expect($client->captured[1]['path'])->toBe('/domains/example.com/records/77');
});

it('cleanup is a no-op when deploy was never called for the domain', function () {
    [$client, $handler] = doHandler('tok', 'example.com', []);

    expect(fn() => $handler->cleanup('example.com', ''))->not->toThrow(\Throwable::class);
    expect($client->captured)->toBeEmpty();
});

it('cleanup clears the stored record ID so a second call is a no-op', function () {
    [$client, $handler] = doHandler('tok', 'example.com', [
        doRecordResponse(1),
        [],
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', '');  // second call: no extra request

    expect($client->captured)->toHaveCount(2);
});

// ── Default client wiring ─────────────────────────────────────────────────────

it('wires the default JsonHttpClient with the correct base URL and auth header', function () {
    $handler = new MockDigitalOceanHandler('my-api-token');

    $clientProp = new ReflectionProperty(DigitalOceanDns01Handler::class, 'httpClient');
    $client     = $clientProp->getValue($handler);

    $baseUrlProp = new ReflectionProperty(JsonHttpClient::class, 'baseUrl');
    $headersProp = new ReflectionProperty(JsonHttpClient::class, 'defaultHeaders');

    expect($baseUrlProp->getValue($client))->toBe('https://api.digitalocean.com/v2');
    expect($headersProp->getValue($client))->toContain('Authorization: Bearer my-api-token');
});
