<?php

use CoyoteCert\Challenge\Dns\Internal\JsonHttpClient;
use CoyoteCert\Exceptions\ChallengeException;

// Subclass that captures what request() passes to send() and replays fixtures.
class TestableJsonHttpClient extends JsonHttpClient
{
    /** @var list<array{method: string, url: string, body: string|null, headers: list<string>}> */
    public array $calls = [];

    /** @var list<array{status: int, raw: string}> */
    private array $responses;

    /**
     * @param list<array{status: int, raw: string}> $responses
     */
    public function __construct(array $responses, string $baseUrl = 'https://api.example.com', array $defaultHeaders = [])
    {
        parent::__construct($baseUrl, $defaultHeaders);
        $this->responses = $responses;
    }

    protected function send(string $method, string $url, ?string $body, array $headers): array
    {
        $this->calls[] = compact('method', 'url', 'body', 'headers');

        $response = array_shift($this->responses);

        if ($response === null) {
            throw new \RuntimeException("Unexpected send(): {$method} {$url}");
        }

        // Reproduce the same status/body checks as the real send()
        if ($response['status'] >= 400) {
            throw new ChallengeException(
                sprintf('API returned HTTP %d for %s %s.', $response['status'], $method, parse_url($url, PHP_URL_PATH) ?: $url),
            );
        }

        $raw = $response['raw'];

        if ($raw === '' || $raw === 'null') {
            return [];
        }

        return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    }
}

function ok(string $raw = '{"result":true}'): array
{
    return ['status' => 200, 'raw' => $raw];
}

function httpError(int $status): array
{
    return ['status' => $status, 'raw' => '{"error":"fail"}'];
}

// ── URL construction ──────────────────────────────────────────────────────────

it('prepends base URL to path', function () {
    $client = new TestableJsonHttpClient([ok()], 'https://api.example.com');
    $client->request('GET', '/zones');

    expect($client->calls[0]['url'])->toBe('https://api.example.com/zones');
});

it('appends query params to the URL for GET requests', function () {
    $client = new TestableJsonHttpClient([ok()]);
    $client->request('GET', '/zones', queryParams: ['name' => 'example.com', 'page' => '1']);

    expect($client->calls[0]['url'])->toContain('name=example.com');
    expect($client->calls[0]['url'])->toContain('page=1');
});

// ── Header construction ───────────────────────────────────────────────────────

it('always includes Content-Type application/json', function () {
    $client = new TestableJsonHttpClient([ok()]);
    $client->request('POST', '/records', ['key' => 'val']);

    expect($client->calls[0]['headers'])->toContain('Content-Type: application/json');
});

it('merges default headers with per-request extra headers', function () {
    $client = new TestableJsonHttpClient([ok()], 'https://api.example.com', ['Authorization: Bearer tok']);
    $client->request('GET', '/zones', extraHeaders: ['X-Custom: yes']);

    expect($client->calls[0]['headers'])->toContain('Authorization: Bearer tok');
    expect($client->calls[0]['headers'])->toContain('X-Custom: yes');
});

// ── Request body ──────────────────────────────────────────────────────────────

it('JSON-encodes the payload as the request body', function () {
    $client = new TestableJsonHttpClient([ok()]);
    $client->request('POST', '/records', ['type' => 'TXT', 'ttl' => 60]);

    expect($client->calls[0]['body'])->toBe('{"type":"TXT","ttl":60}');
});

it('sends null body when no payload is given', function () {
    $client = new TestableJsonHttpClient([ok()]);
    $client->request('GET', '/zones');

    expect($client->calls[0]['body'])->toBeNull();
});

// ── Response decoding ─────────────────────────────────────────────────────────

it('returns empty array for empty response body', function () {
    $client = new TestableJsonHttpClient([ok('')]);
    $result = $client->request('DELETE', '/records/1');

    expect($result)->toBe([]);
});

it('returns empty array for null response body', function () {
    $client = new TestableJsonHttpClient([ok('null')]);
    $result = $client->request('DELETE', '/records/1');

    expect($result)->toBe([]);
});

it('decodes JSON response into an array', function () {
    $client = new TestableJsonHttpClient([ok('{"result":{"id":"abc"},"success":true}')]);
    $result = $client->request('GET', '/zones');

    expect($result['result']['id'])->toBe('abc');
});

// ── Error handling ────────────────────────────────────────────────────────────

it('throws ChallengeException on HTTP 4xx', function () {
    $client = new TestableJsonHttpClient([httpError(403)]);

    expect(fn() => $client->request('POST', '/records'))
        ->toThrow(ChallengeException::class, 'HTTP 403');
});

it('throws ChallengeException on HTTP 5xx', function () {
    $client = new TestableJsonHttpClient([httpError(500)]);

    expect(fn() => $client->request('GET', '/zones'))
        ->toThrow(ChallengeException::class, 'HTTP 500');
});

// ── Real send() via curl namespace stubs ──────────────────────────────────────
// The following tests exercise JsonHttpClient::send() directly (no TestableJsonHttpClient
// override). The curl_* stubs in tests/Pest.php intercept all curl calls so no
// real HTTP connection is made. $GLOBALS['__test_curl'] activates the stubs;
// afterEach() clears it so fixture state never leaks across tests.

afterEach(function () {
    unset($GLOBALS['__test_curl']);
});

it('send() throws when curl fails to initialise', function () {
    $GLOBALS['__test_curl'] = ['init' => false];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect(fn() => $client->request('GET', '/zones'))
        ->toThrow(ChallengeException::class, 'Failed to initialise cURL');
});

it('send() throws on connection error', function () {
    $GLOBALS['__test_curl'] = ['body' => false, 'status' => 0, 'error' => 'Connection timed out'];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect(fn() => $client->request('GET', '/zones'))
        ->toThrow(ChallengeException::class, 'Connection timed out');
});

it('send() decodes a successful JSON response', function () {
    $GLOBALS['__test_curl'] = ['body' => '{"id":"zone-1"}', 'status' => 200];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect($client->request('GET', '/zones'))->toBe(['id' => 'zone-1']);
});

it('send() returns empty array for an empty body', function () {
    $GLOBALS['__test_curl'] = ['body' => '', 'status' => 200];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect($client->request('DELETE', '/records/1'))->toBe([]);
});

it('send() throws on HTTP 4xx from the real send path', function () {
    $GLOBALS['__test_curl'] = ['body' => '{"error":"forbidden"}', 'status' => 403];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect(fn() => $client->request('POST', '/zones'))
        ->toThrow(ChallengeException::class, 'HTTP 403');
});

it('send() exercises the POST-with-body curl branch', function () {
    $GLOBALS['__test_curl'] = ['body' => '{"created":true}', 'status' => 200];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect($client->request('POST', '/records', ['type' => 'TXT']))->toBe(['created' => true]);
});

it('send() exercises the POST-without-body curl branch', function () {
    $GLOBALS['__test_curl'] = ['body' => '{"ok":true}', 'status' => 200];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect($client->request('POST', '/trigger'))->toBe(['ok' => true]);
});

it('send() exercises the DELETE curl branch', function () {
    $GLOBALS['__test_curl'] = ['body' => '', 'status' => 200];
    $client                 = new JsonHttpClient('https://api.example.com');

    expect($client->request('DELETE', '/records/42'))->toBe([]);
});
