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

    expect(fn() => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->not->toThrow(DomainValidationException::class);
});

it('http brackets IPv6 identifiers in the URL and follows up to 10 redirects', function () {
    $client = new class implements HttpClientInterface {
        public string $url       = '';
        public int $maxRedirects = 0;

        public function head(string $url): Response
        {
            return new Response([], $url, 200, '');
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            [$this->url, $this->maxRedirects] = [$url, $maxRedirects];

            return new Response([], $url, 200, 'tok.thumb');
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, '');
        }
    };

    LocalChallengeTest::http('2001:db8::1', 'tok', 'tok.thumb', $client);

    expect($client->url)->toBe('http://[2001:db8::1]/.well-known/acme-challenge/tok');
    expect($client->maxRedirects)->toBe(10);
});

it('http passes when body has surrounding whitespace', function () {
    $client = makeHttpClient(200, "  tokenABC.thumbprint\n");

    expect(fn() => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->not->toThrow(\Throwable::class);
});

it('http throws when body does not match keyAuthorization', function () {
    $client = makeHttpClient(200, 'wrong-content');

    expect(fn() => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->toThrow(DomainValidationException::class);
});

it('http throws when server returns a non-200 response', function () {
    $client = makeHttpClient(404, 'Not Found');

    expect(fn() => LocalChallengeTest::http('example.com', 'tokenABC', 'tokenABC.thumbprint', $client))
        ->toThrow(DomainValidationException::class);
});

it('http encodes array body to JSON before comparing', function () {
    // If the HTTP client returns a decoded JSON array, LocalChallengeTest re-encodes it.
    // Simulate a case where it would fail (array body != keyAuth string).
    $client = makeHttpClient(200, ['some' => 'json']);

    expect(fn() => LocalChallengeTest::http('example.com', 'token', 'token.thumbprint', $client))
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

// ── Private method coverage via reflection ────────────────────────────────────

it('validateTxtRecords returns true when a record txt() matches the expected value', function () {
    // A duck-typed record with txt() is all that validateTxtRecords() needs
    $matchingRecord = new class {
        public function txt(): string
        {
            return 'expected-digest';
        }
    };
    $nonMatchingRecord = new class {
        public function txt(): string
        {
            return 'wrong-digest';
        }
    };

    $method = new \ReflectionMethod(LocalChallengeTest::class, 'validateTxtRecords');

    expect($method->invoke(null, [$matchingRecord], 'expected-digest'))->toBeTrue();
    expect($method->invoke(null, [$nonMatchingRecord], 'expected-digest'))->toBeFalse();
    expect($method->invoke(null, [], 'expected-digest'))->toBeFalse();
});

// ── dns() integration path (Spatie\Dns calls will fail / throw RuntimeException) ──

it('dns() throws DomainValidationException when no DNS record matches', function () {
    // Calling LocalChallengeTest::dns() without a real TXT record will either
    // fail DNS resolution (RuntimeException swallowed) or find no matching value,
    // and must throw DomainValidationException.
    expect(fn() => LocalChallengeTest::dns('invalid.example.test', '_acme-challenge', 'somevalue'))
        ->toThrow(DomainValidationException::class);
});

// ── followCname() via reflection ──────────────────────────────────────────────

it('followCname() stops after 10 hops without querying DNS', function () {
    $method = new \ReflectionMethod(LocalChallengeTest::class, 'followCname');

    expect($method->invoke(null, 'ns.example.test', '_acme-challenge.example.test', 10))->toBe([]);
});

// ── getRecords() via reflection ───────────────────────────────────────────────

it('getRecords() returns an array (may be empty for non-existent domain)', function () {
    $method = new \ReflectionMethod(LocalChallengeTest::class, 'getRecords');

    // Use a nameserver and domain that will return an empty result or throw;
    // the important thing is that getRecords() either returns [] or throws RuntimeException.
    try {
        $records = $method->invoke(null, 'dns.google.com', 'invalid.example.test', DNS_TXT);
        expect($records)->toBeArray();
    } catch (\RuntimeException) {
        expect(true)->toBeTrue(); // DNS lookup failure is acceptable
    }
});
