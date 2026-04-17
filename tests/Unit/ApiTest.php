<?php

use CoyoteCert\Api;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Http\Client;
use CoyoteCert\Http\Response;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\CustomProvider;
use CoyoteCert\Storage\InMemoryStorage;
use Psr\Log\NullLogger;

function makeProvider(): CustomProvider
{
    return new CustomProvider(directoryUrl: 'https://acme.example/directory');
}

function makeApi(?InMemoryStorage $storage = null, ?HttpClientInterface $httpClient = null): Api
{
    return new Api(
        provider: makeProvider(),
        storage: $storage,
        httpClient: $httpClient,
    );
}

// ── accountAdapter() ─────────────────────────────────────────────────────────

it('accountAdapter() throws when no storage is configured', function () {
    $api = makeApi(storage: null);

    expect(fn() => $api->accountAdapter())
        ->toThrow(AcmeException::class, 'No storage configured');
});

// ── getHttpClient() ───────────────────────────────────────────────────────────

it('getHttpClient() lazily initialises a Client instance', function () {
    $api = makeApi();

    expect($api->getHttpClient())->toBeInstanceOf(Client::class);
});

it('getHttpClient() returns the same instance on repeated calls', function () {
    $api = makeApi();

    expect($api->getHttpClient())->toBe($api->getHttpClient());
});

// ── setHttpClient() ───────────────────────────────────────────────────────────

it('setHttpClient() returns self (fluent)', function () {
    $api  = makeApi();
    $mock = new class implements HttpClientInterface {
        public function head(string $url): Response
        {
            return new Response([], $url, 200, '');
        }
        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, []);
        }
        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, []);
        }
    };

    expect($api->setHttpClient($mock))->toBe($api);
});

it('setHttpClient() replaces the http client', function () {
    $api  = makeApi();
    $mock = new class implements HttpClientInterface {
        public function head(string $url): Response
        {
            return new Response([], $url, 200, '');
        }
        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, []);
        }
        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, []);
        }
    };

    $api->setHttpClient($mock);

    expect($api->getHttpClient())->toBe($mock);
});

// ── setLogger() ───────────────────────────────────────────────────────────────

it('setLogger() returns self (fluent)', function () {
    $api = makeApi();

    expect($api->setLogger(new NullLogger()))->toBe($api);
});

// ── logger() ──────────────────────────────────────────────────────────────────

it('logger() dispatches to a configured logger without throwing', function () {
    $api = makeApi();
    $api->setLogger(new NullLogger());

    // NullLogger silently discards the message; we just assert no exception is thrown.
    expect(fn() => $api->logger('info', 'test message', ['key' => 'value']))->not->toThrow(\Throwable::class);
});

it('logger() is a no-op when no logger is configured', function () {
    $api = makeApi();

    expect(fn() => $api->logger('error', 'no logger set'))->not->toThrow(\Throwable::class);
});
