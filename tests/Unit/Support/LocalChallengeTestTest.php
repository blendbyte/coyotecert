<?php

declare(strict_types=1);

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

it('http brackets IPv6 identifiers in the URL', function () {
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
    expect($client->maxRedirects)->toBe(0); // redirects are followed by the self-test itself
});

/** Answers each URL from $routes: [status, Location or body]; records the URLs requested. */
function redirectingClient(array $routes): HttpClientInterface
{
    return new class ($routes) implements HttpClientInterface {
        public array $requested = [];

        public function __construct(private array $routes) {}

        public function head(string $url): Response
        {
            return new Response([], $url, 200, '');
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            $this->requested[] = $url;
            [$status, $value]  = $this->routes[$url] ?? [404, ''];

            return $status >= 300 && $status < 400
                ? new Response(['location' => $value], $url, $status, '')
                : new Response([], $url, $status, $value);
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, '');
        }
    };
}

it('http follows redirects to http/https on ports 80 and 443, resolving relative locations', function () {
    $client = redirectingClient([
        'http://example.com/.well-known/acme-challenge/tok' => [301, '//www.example.com/a/tok'],
        'http://www.example.com/a/tok'                      => [302, '/b/tok'],
        'http://www.example.com/b/tok'                      => [307, 'https://www.example.com:443/acme/tok'],
        'https://www.example.com:443/acme/tok'              => [302, 'final'],
        'https://www.example.com:443/acme/final'            => [200, 'tok.thumb'],
    ]);

    LocalChallengeTest::http('example.com', 'tok', 'tok.thumb', $client);

    expect($client->requested)->toHaveCount(5);
});

it('http refuses redirects the CA would not follow', function (string $location) {
    $client = redirectingClient(['http://example.com/.well-known/acme-challenge/tok' => [302, $location]]);

    expect(fn() => LocalChallengeTest::http('example.com', 'tok', 'tok.thumb', $client))
        ->toThrow(DomainValidationException::class, 'which the CA does not follow');
    expect($client->requested)->toHaveCount(1);
})->with([
    'internal port' => ['http://127.0.0.1:8080/admin'],
    'other scheme'  => ['gopher://127.0.0.1:6379/_FLUSHALL'],
    'file'          => ['file:///etc/passwd'],
]);

it('http stops after 10 redirects', function () {
    $routes = [];
    for ($i = 0; $i <= 11; $i++) {
        $from          = $i === 0 ? 'http://example.com/.well-known/acme-challenge/tok' : "http://example.com/r{$i}";
        $routes[$from] = [302, 'http://example.com/r' . ($i + 1)];
    }
    $client = redirectingClient($routes);

    expect(fn() => LocalChallengeTest::http('example.com', 'tok', 'tok.thumb', $client))
        ->toThrow(DomainValidationException::class, '302 status code');
    expect($client->requested)->toHaveCount(11);
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

it('http reports a connection failure as a DomainValidationException', function () {
    $client = new class implements HttpClientInterface {
        public function head(string $url): Response
        {
            throw new \CoyoteCert\Exceptions\AcmeException('GET failed: Connection refused');
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            throw new \CoyoteCert\Exceptions\AcmeException('GET failed: Connection refused');
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            throw new \CoyoteCert\Exceptions\AcmeException('unused');
        }
    };

    expect(fn() => LocalChallengeTest::http('example.com', 'tok', 'tok.thumb', $client))
        ->toThrow(DomainValidationException::class, 'could not connect: GET failed: Connection refused');
});
