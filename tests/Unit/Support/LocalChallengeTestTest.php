<?php

use CoyoteCert\Exceptions\DomainValidationException;
use CoyoteCert\Http\Response;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Support\LocalChallengeTest;

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeHttpClient(int $code, string|array $body): HttpClientInterface
{
    return new class ($code, $body) implements HttpClientInterface {
        public function __construct(private int $code, private string|array $body) {}

        public function head(string $url): Response
        {
            return new Response([], $url, $this->code, $this->body);
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, $this->code, $this->body);
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, $this->code, $this->body);
        }
    };
}

// ── LocalChallengeTest::http() ────────────────────────────────────────────────

it('http passes when body matches keyAuthorization', function () {
    $client = makeHttpClient(200, 'tokenABC.thumbprint');

    expect(fn () => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->not->toThrow(DomainValidationException::class);
});

it('http passes when body has surrounding whitespace', function () {
    $client = makeHttpClient(200, "  tokenABC.thumbprint\n");

    expect(fn () => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->not->toThrow(\Throwable::class);
});

it('http throws when body does not match keyAuthorization', function () {
    $client = makeHttpClient(200, 'wrong-content');

    expect(fn () => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->toThrow(DomainValidationException::class);
});

it('http throws when server returns a non-200 response', function () {
    $client = makeHttpClient(404, 'Not Found');

    expect(fn () => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->toThrow(DomainValidationException::class);
});

it('http encodes array body to JSON before comparing', function () {
    // If the HTTP client returns a decoded JSON array, LocalChallengeTest re-encodes it.
    // Simulate a case where it would fail (array body != keyAuth string).
    $client = makeHttpClient(200, ['some' => 'json']);

    expect(fn () => LocalChallengeTest::http('example.com', 'token', 'token.thumbprint', $client))
        ->toThrow(DomainValidationException::class);
});

// ── DomainValidationException factory methods ─────────────────────────────────

it('localHttpChallengeTestFailed includes domain and status code in message', function () {
    $e = DomainValidationException::localHttpChallengeTestFailed('example.com', '404');

    expect($e)->toBeInstanceOf(DomainValidationException::class);
    expect($e->getMessage())->toContain('example.com');
    expect($e->getMessage())->toContain('404');
});

it('localDnsChallengeTestFailed includes domain in message', function () {
    $e = DomainValidationException::localDnsChallengeTestFailed('example.com');

    expect($e)->toBeInstanceOf(DomainValidationException::class);
    expect($e->getMessage())->toContain('example.com');
});
