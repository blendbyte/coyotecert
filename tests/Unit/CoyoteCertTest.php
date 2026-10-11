<?php

use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Provider\Pebble;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Storage\StoredCertificate;
use Psr\Log\NullLogger;

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeCoyote(): CoyoteCert
{
    return CoyoteCert::with(new Pebble());
}

function makeCoyoteCert(string $caBundle = '', int $expiresInDays = 90): StoredCertificate
{
    return new StoredCertificate(
        certificate: 'cert-pem',
        privateKey: 'key-pem',
        fullchain: 'fullchain-pem',
        caBundle: $caBundle,
        issuedAt: new DateTimeImmutable(),
        expiresAt: new DateTimeImmutable("+{$expiresInDays} days"),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    );
}

function makeNoOpHandler(AuthorizationChallengeEnum $supports = AuthorizationChallengeEnum::HTTP): ChallengeHandlerInterface
{
    return new class ($supports) implements ChallengeHandlerInterface {
        public function __construct(private AuthorizationChallengeEnum $type) {}
        public function supports(AuthorizationChallengeEnum $t): bool
        {
            return $t === $this->type;
        }
        public function deploy(string $d, string $tok, string $auth): void {}
        public function cleanup(string $d, string $tok): void {}
    };
}

// ── Builder methods ───────────────────────────────────────────────────────────

it('with() returns a CoyoteCert instance', function () {
    expect(CoyoteCert::with(new Pebble()))->toBeInstanceOf(CoyoteCert::class);
});

it('email() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->email('admin@example.com'))->toBe($c);
});

it('logger() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->logger(new NullLogger()))->toBe($c);
});

it('keyType() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->keyType(KeyType::RSA_2048))->toBe($c);
});

it('accountKeyType() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->accountKeyType(KeyType::EC_P256))->toBe($c);
});

it('skipLocalTest() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->skipLocalTest())->toBe($c);
});

it('skipCaaCheck() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->skipCaaCheck())->toBe($c);
});

it('preferredChain() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->preferredChain('ISRG Root X1'))->toBe($c);
});

it('profile() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->profile('shortlived'))->toBe($c);
});

it('httpClient() returns self (fluent)', function () {
    $factory = new \Nyholm\Psr7\Factory\Psr17Factory();
    $stub    = new class implements \Psr\Http\Client\ClientInterface {
        public function sendRequest(\Psr\Http\Message\RequestInterface $r): \Psr\Http\Message\ResponseInterface
        {
            throw new \RuntimeException('not implemented');
        }
    };

    $c = makeCoyote();
    expect($c->httpClient($stub, $factory, $factory))->toBe($c);
});

it('storage() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->storage(new InMemoryStorage()))->toBe($c);
});

it('challenge() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->challenge(makeNoOpHandler()))->toBe($c);
});

it('identifiers() accepts a string', function () {
    $c = makeCoyote();
    expect($c->identifiers('example.com'))->toBe($c);
});

it('identifiers() accepts an array', function () {
    $c = makeCoyote();
    expect($c->identifiers(['example.com', 'www.example.com']))->toBe($c);
});

it('identifiers() accepts a wildcard domain', function () {
    $c = makeCoyote();
    expect($c->identifiers('*.example.com'))->toBe($c);
});

it('identifiers() accepts an IPv4 address', function () {
    $c = makeCoyote();
    expect($c->identifiers('192.0.2.1'))->toBe($c);
});

it('identifiers() accepts an IPv6 address', function () {
    $c = makeCoyote();
    expect($c->identifiers('2001:db8::1'))->toBe($c);
});

it('identifiers() accepts a mix of domain names and IP addresses', function () {
    $c = makeCoyote();
    expect($c->identifiers(['example.com', '192.0.2.1', '2001:db8::1']))->toBe($c);
});

// ── SEC-05: domain name validation ───────────────────────────────────────────

it('identifiers() throws AcmeException for a domain containing a newline', function () {
    expect(fn() => makeCoyote()->identifiers("evil.com\ninjected"))
        ->toThrow(AcmeException::class, 'Invalid domain name');
});

it('identifiers() throws AcmeException for a domain containing a slash', function () {
    expect(fn() => makeCoyote()->identifiers('evil.com/path'))
        ->toThrow(AcmeException::class, 'Invalid domain name');
});

it('identifiers() throws AcmeException for a bare TLD', function () {
    expect(fn() => makeCoyote()->identifiers('com'))
        ->toThrow(AcmeException::class, 'Invalid domain name');
});

it('identifiers() throws AcmeException for an empty string', function () {
    expect(fn() => makeCoyote()->identifiers(''))
        ->toThrow(AcmeException::class, 'Invalid domain name');
});

it('identifiers() throws AcmeException for a double wildcard', function () {
    expect(fn() => makeCoyote()->identifiers('*.*.example.com'))
        ->toThrow(AcmeException::class, 'Invalid domain name');
});

// ── detectChallengeType() ─────────────────────────────────────────────────────

it('detectChallengeType() throws when the handler supports no known challenge type', function () {
    $noneHandler = new class implements ChallengeHandlerInterface {
        public function supports(AuthorizationChallengeEnum $t): bool
        {
            return false;
        }
        public function deploy(string $d, string $tok, string $auth): void {}
        public function cleanup(string $d, string $tok): void {}
    };

    $coyote = makeCoyote()->challenge($noneHandler);
    $method = new \ReflectionMethod(CoyoteCert::class, 'detectChallengeType');

    expect(fn() => $method->invoke($coyote))
        ->toThrow(AcmeException::class, 'does not support any known challenge type');
});

// ── validate() / issue() guard ────────────────────────────────────────────────

it('issue() throws when no identifiers are configured', function () {
    expect(fn() => makeCoyote()->challenge(makeNoOpHandler())->issue())
        ->toThrow(AcmeException::class, 'No identifiers');
});

it('issue() throws when no challenge handler is configured', function () {
    expect(fn() => makeCoyote()->identifiers('example.com')->issue())
        ->toThrow(AcmeException::class, 'No challenge handler');
});

// ── revoke() guard ────────────────────────────────────────────────────────────

it('revoke() throws when no storage is configured', function () {
    expect(fn() => makeCoyote()->revoke(makeCoyoteCert()))
        ->toThrow(AcmeException::class, 'No storage');
});

// ── needsRenewal() ────────────────────────────────────────────────────────────

it('needsRenewal() returns true when no storage is configured', function () {
    expect(makeCoyote()->identifiers('example.com')->needsRenewal())->toBeTrue();
});

it('needsRenewal() returns true when no certificate is stored', function () {
    $storage = new InMemoryStorage();

    expect(
        makeCoyote()->identifiers('example.com')->storage($storage)->needsRenewal(),
    )->toBeTrue();
});

it('needsRenewal() returns false when certificate has plenty of time remaining', function () {
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(expiresInDays: 90));

    expect(
        makeCoyote()->identifiers('example.com')->storage($storage)->needsRenewal(30),
    )->toBeFalse();
});

it('needsRenewal() returns true when certificate expires within the threshold', function () {
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(expiresInDays: 10));

    expect(
        makeCoyote()->identifiers('example.com')->storage($storage)->needsRenewal(30),
    )->toBeTrue();
});

// ── issueOrRenew() ────────────────────────────────────────────────────────────

it('issueOrRenew() returns existing cert when renewal is not needed', function () {
    $storage = new InMemoryStorage();
    $cert    = makeCoyoteCert(expiresInDays: 90);
    $storage->saveCertificate('example.com', $cert);

    $result = makeCoyote()
        ->identifiers('example.com')
        ->storage($storage)
        ->challenge(makeNoOpHandler())
        ->issueOrRenew(30);

    expect($result->certificate)->toBe('cert-pem');
});

it('issueOrRenew() calls issue() when renewal is needed', function () {
    // needsRenewal() returns true (no storage) → line 380 `return $this->issue()` is hit
    // → issue() throws at the "No identifiers" guard
    expect(fn() => makeCoyote()->challenge(makeNoOpHandler())->issueOrRenew())
        ->toThrow(AcmeException::class, 'No identifiers');
});

// ── ariWindow() (tested via needsRenewal()) ───────────────────────────────────

it('needsRenewal() falls back to remainingDays when the certificate cannot be parsed for ARI', function () {
    // certId() throws on the unparsable certificate, so ariWindow() returns null
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(caBundle: 'not-a-pem', expiresInDays: 90));

    expect(
        makeCoyote()->identifiers('example.com')->storage($storage)->needsRenewal(30),
    )->toBeFalse();
});

it('needsRenewal() returns null from ariWindow when API call throws (catch block)', function () {
    // A failing HTTP client causes the directory GET to throw, which ariWindow() catches.
    $fakeCaBundle = "-----BEGIN CERTIFICATE-----\nMIIBtest==\n-----END CERTIFICATE-----";

    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(caBundle: $fakeCaBundle, expiresInDays: 90));

    // PSR-18 client that always throws — forces the try/catch in ariWindow().
    $factory      = new \Nyholm\Psr7\Factory\Psr17Factory();
    $failingPsr18 = new class implements \Psr\Http\Client\ClientInterface {
        public function sendRequest(\Psr\Http\Message\RequestInterface $r): \Psr\Http\Message\ResponseInterface
        {
            throw new \RuntimeException('Connection refused');
        }
    };

    $result = makeCoyote()
        ->httpClient($failingPsr18, $factory, $factory)
        ->identifiers('example.com')
        ->storage($storage)
        ->needsRenewal(30);

    // ariWindow() returns null (exception caught) → falls back to remainingDays()
    // 90 days > 30 threshold → not needing renewal.
    expect($result)->toBeFalse();
});

it('needsRenewal() returns $window->isOpen() when ARI returns a valid renewal window', function () {
    [$certPem, $issuerPem] = caSignedLeaf();

    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', new StoredCertificate(
        certificate: $certPem,
        privateKey: 'key-pem',
        fullchain: $certPem . $issuerPem,
        caBundle: $issuerPem,
        issuedAt: new DateTimeImmutable(),
        expiresAt: new DateTimeImmutable('+10 days'),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    ));

    $factory   = new \Nyholm\Psr7\Factory\Psr17Factory();
    $callCount = 0;

    $mockClient = new class ($factory, $callCount) implements \Psr\Http\Client\ClientInterface {
        public int $calls = 0;

        public function __construct(private \Nyholm\Psr7\Factory\Psr17Factory $factory, int $_) {}

        public function sendRequest(\Psr\Http\Message\RequestInterface $r): \Psr\Http\Message\ResponseInterface
        {
            $this->calls++;
            $body = match ($this->calls) {
                // First call: directory with renewalInfo URL
                1 => json_encode([
                    'newNonce'    => 'https://acme.example/nonce',
                    'newAccount'  => 'https://acme.example/new-account',
                    'newOrder'    => 'https://acme.example/new-order',
                    'revokeCert'  => 'https://acme.example/revoke',
                    'renewalInfo' => 'https://acme.example/ari',
                ]),
                // Second call: ARI response — window far in the future (not open)
                default => json_encode([
                    'suggestedWindow' => [
                        'start' => '2099-01-01T00:00:00Z',
                        'end'   => '2099-06-01T00:00:00Z',
                    ],
                    'explanationURL' => 'https://acme.example/why',
                ]),
            };

            return $this->factory->createResponse(200)
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->factory->createStream($body));
        }
    };

    $result = makeCoyote()
        ->httpClient($mockClient, $factory, $factory)
        ->identifiers('example.com')
        ->storage($storage)
        ->needsRenewal(30);

    // ARI window is far in the future, so no renewal even though only 10 days remain
    expect($result)->toBeFalse();
    expect($mockClient->calls)->toBe(2);
});

// ── withHttpTimeout() ─────────────────────────────────────────────────────────

it('withHttpTimeout() creates an HttpClient when no HTTP client is configured', function () {
    $coyote = makeCoyote()->withHttpTimeout(30);

    $ref    = new \ReflectionProperty(CoyoteCert::class, 'httpClient');
    $client = $ref->getValue($coyote);

    expect($client)->toBeInstanceOf(\CoyoteCert\Http\Client::class);
});

it('withHttpTimeout() calls setTimeout on an already-configured HttpClient', function () {
    $coyote = makeCoyote()->withHttpTimeout(5); // creates an HttpClient (null branch)
    $coyote->withHttpTimeout(30);              // updates it (instanceof branch)

    $clientRef  = new \ReflectionProperty(CoyoteCert::class, 'httpClient');
    $timeoutRef = new \ReflectionProperty(\CoyoteCert\Http\Client::class, 'timeout');

    $client = $clientRef->getValue($coyote);
    expect($timeoutRef->getValue($client))->toBe(30);
});

// ── onIssued() / onRenewed() ──────────────────────────────────────────────────

it('onIssued() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->onIssued(fn($cert) => null))->toBe($c);
});

it('onRenewed() returns self (fluent)', function () {
    $c = makeCoyote();
    expect($c->onRenewed(fn($cert) => null))->toBe($c);
});

it('onIssued() registers multiple callbacks', function () {
    $c = makeCoyote();
    $c->onIssued(fn($cert) => null);
    $c->onIssued(fn($cert) => null);

    $ref = new \ReflectionProperty(CoyoteCert::class, 'onIssuedCallbacks');
    expect($ref->getValue($c))->toHaveCount(2);
});

it('onRenewed() registers multiple callbacks', function () {
    $c = makeCoyote();
    $c->onRenewed(fn($cert) => null);
    $c->onRenewed(fn($cert) => null);

    $ref = new \ReflectionProperty(CoyoteCert::class, 'onRenewedCallbacks');
    expect($ref->getValue($c))->toHaveCount(2);
});

it('fireIssuedCallbacks() invokes onIssued callbacks with the certificate', function () {
    $cert     = makeCoyoteCert();
    $coyote   = makeCoyote();
    $received = null;

    $coyote->onIssued(function ($c) use (&$received) {
        $received = $c;
    });

    $method = new \ReflectionMethod(CoyoteCert::class, 'fireIssuedCallbacks');
    $method->invoke($coyote, $cert, false);

    expect($received)->toBe($cert);
});

it('fireIssuedCallbacks() does not invoke onRenewed callbacks when isRenewal is false', function () {
    $cert   = makeCoyoteCert();
    $coyote = makeCoyote();
    $called = false;

    $coyote->onRenewed(function () use (&$called) {
        $called = true;
    });

    $method = new \ReflectionMethod(CoyoteCert::class, 'fireIssuedCallbacks');
    $method->invoke($coyote, $cert, false);

    expect($called)->toBeFalse();
});

it('fireIssuedCallbacks() invokes onRenewed callbacks when isRenewal is true', function () {
    $cert     = makeCoyoteCert();
    $coyote   = makeCoyote();
    $received = null;

    $coyote->onRenewed(function ($c) use (&$received) {
        $received = $c;
    });

    $method = new \ReflectionMethod(CoyoteCert::class, 'fireIssuedCallbacks');
    $method->invoke($coyote, $cert, true);

    expect($received)->toBe($cert);
});

it('fireIssuedCallbacks() invokes both onIssued and onRenewed when isRenewal is true', function () {
    $cert   = makeCoyoteCert();
    $coyote = makeCoyote();
    $log    = [];

    $coyote->onIssued(function () use (&$log) {
        $log[] = 'issued';
    });
    $coyote->onRenewed(function () use (&$log) {
        $log[] = 'renewed';
    });

    $method = new \ReflectionMethod(CoyoteCert::class, 'fireIssuedCallbacks');
    $method->invoke($coyote, $cert, true);

    expect($log)->toBe(['issued', 'renewed']);
});

it('fireIssuedCallbacks() invokes callbacks in registration order', function () {
    $cert   = makeCoyoteCert();
    $coyote = makeCoyote();
    $log    = [];

    $coyote->onIssued(function () use (&$log) {
        $log[] = 1;
    });
    $coyote->onIssued(function () use (&$log) {
        $log[] = 2;
    });
    $coyote->onIssued(function () use (&$log) {
        $log[] = 3;
    });

    $method = new \ReflectionMethod(CoyoteCert::class, 'fireIssuedCallbacks');
    $method->invoke($coyote, $cert, false);

    expect($log)->toBe([1, 2, 3]);
});

// ── extractTokenAndKeyAuth() ──────────────────────────────────────────────────

it('extractTokenAndKeyAuth() returns [name, value] for Dns01ValidationData', function () {
    $coyote = makeCoyote();
    $method = new \ReflectionMethod(CoyoteCert::class, 'extractTokenAndKeyAuth');

    $dns = new \CoyoteCert\DTO\Dns01ValidationData(
        identifier: 'example.com',
        name: '_acme-challenge',
        value: 'expected-digest',
        keyAuthorization: 'expected-digest',
    );

    [$token, $auth] = $method->invoke($coyote, $dns);

    expect($token)->toBe('_acme-challenge');
    expect($auth)->toBe('expected-digest');
});

it('extractTokenAndKeyAuth() returns [filename, content] for Http01ValidationData', function () {
    $coyote = makeCoyote();
    $method = new \ReflectionMethod(CoyoteCert::class, 'extractTokenAndKeyAuth');

    $http = new \CoyoteCert\DTO\Http01ValidationData(
        identifier: 'example.com',
        filename: 'token-file',
        content: 'token.keyauth',
        keyAuthorization: 'token.keyauth',
    );

    [$token, $auth] = $method->invoke($coyote, $http);

    expect($token)->toBe('token-file');
    expect($auth)->toBe('token.keyauth');
});

it('extractTokenAndKeyAuth() returns [token, keyAuthorization] for TlsAlpn01ValidationData', function () {
    $coyote = makeCoyote();
    $method = new \ReflectionMethod(CoyoteCert::class, 'extractTokenAndKeyAuth');

    $tls = new \CoyoteCert\DTO\TlsAlpn01ValidationData(
        identifier: 'example.com',
        token: 'tls-token',
        keyAuthorization: 'tls-token.keyauth',
    );

    [$token, $auth] = $method->invoke($coyote, $tls);

    expect($token)->toBe('tls-token');
    expect($auth)->toBe('tls-token.keyauth');
});

// ── deployAndValidate() cleanup ───────────────────────────────────────────────

/**
 * Mock ACME server with one pending http-01 authorization per domain. Challenge
 * submissions answer with $challengeCode; once submitted, the authorization is valid.
 */
function cleanupTestApi(array $domains, int $challengeCode): \CoyoteCert\Api
{
    $storage = new InMemoryStorage();
    $storage->saveAccountKey((new Pebble())->getSlug(), rsaKeyPem(), KeyType::RSA_2048);

    $http = new class ($domains, $challengeCode) implements \CoyoteCert\Interfaces\HttpClientInterface {
        private bool $submitted = false;

        public function __construct(private array $domains, private int $challengeCode) {}

        public function head(string $url): \CoyoteCert\Http\Response
        {
            return new \CoyoteCert\Http\Response(['replay-nonce' => 'nonce'], $url, 200, '');
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): \CoyoteCert\Http\Response
        {
            return new \CoyoteCert\Http\Response([], $url, 200, ['newNonce' => 'https://acme.example/nonce']);
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): \CoyoteCert\Http\Response
        {
            if (str_contains($url, '/chall/')) {
                $this->submitted = $this->challengeCode < 400;

                return new \CoyoteCert\Http\Response([], $url, $this->challengeCode, ['detail' => 'Challenge rejected']);
            }

            $i = (int) basename($url);

            return new \CoyoteCert\Http\Response([], $url, 200, [
                'identifier' => ['type' => 'dns', 'value' => $this->domains[$i]],
                'status'     => $this->submitted ? 'valid' : 'pending',
                'expires'    => '2099-01-01T00:00:00Z',
                'challenges' => [['type' => 'http-01', 'token' => "tok{$i}", 'url' => "https://acme.example/chall/{$i}"]],
            ]);
        }
    };

    return new \CoyoteCert\Api(provider: new Pebble(), storage: $storage, httpClient: $http);
}

function recordingHandler(bool $failCleanup = false): ChallengeHandlerInterface
{
    return new class ($failCleanup) implements ChallengeHandlerInterface {
        public array $deployed = [];
        public array $cleaned  = [];

        public function __construct(private bool $failCleanup) {}

        public function supports(AuthorizationChallengeEnum $t): bool
        {
            return $t === AuthorizationChallengeEnum::HTTP;
        }

        public function deploy(string $d, string $tok, string $auth): void
        {
            $this->deployed[] = $d;
        }

        public function cleanup(string $d, string $tok): void
        {
            $this->cleaned[] = $d;

            if ($this->failCleanup) {
                throw new RuntimeException("cleanup failed for {$d}");
            }
        }
    };
}

function invokeDeployAndValidate(CoyoteCert $coyote, \CoyoteCert\Api $api, array $domains): void
{
    $order = new \CoyoteCert\DTO\OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: array_map(fn($i) => "https://acme.example/authz/{$i}", array_keys($domains)),
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: null,
        finalized: false,
    );
    $account = new \CoyoteCert\DTO\AccountData(
        id: '1',
        url: 'https://acme.example/account/1',
        key: [],
        status: 'valid',
        agreement: '',
        createdAt: null,
    );

    $method = new \ReflectionMethod(CoyoteCert::class, 'deployAndValidate');
    $method->invoke($coyote, $api, $order, $account, (new \ReflectionProperty(CoyoteCert::class, 'challengeHandler'))->getValue($coyote));
}

it('deployAndValidate() cleans up every deployed challenge when challenge submission fails', function () {
    $domains = ['a.example.com', 'b.example.com'];
    $handler = recordingHandler();
    $coyote  = makeCoyote()->identifiers($domains)->challenge($handler)->skipLocalTest();

    expect(fn() => invokeDeployAndValidate($coyote, cleanupTestApi($domains, 400), $domains))
        ->toThrow(AcmeException::class, 'Challenge rejected');

    expect($handler->deployed)->toBe($domains);
    expect($handler->cleaned)->toBe($domains);
});

it('deployAndValidate() keeps cleaning up and succeeds when a cleanup call throws', function () {
    $domains = ['a.example.com', 'b.example.com'];
    $handler = recordingHandler(failCleanup: true);
    $coyote  = makeCoyote()->identifiers($domains)->challenge($handler)->skipLocalTest();

    invokeDeployAndValidate($coyote, cleanupTestApi($domains, 200), $domains);

    expect($handler->cleaned)->toBe($domains);
});

it('issue() works without storage and registers an account with a throwaway key', function () {
    $factory = new \Nyholm\Psr7\Factory\Psr17Factory();
    $client  = new class ($factory) implements \Psr\Http\Client\ClientInterface {
        public array $posted = [];

        public function __construct(private \Nyholm\Psr7\Factory\Psr17Factory $factory) {}

        public function sendRequest(\Psr\Http\Message\RequestInterface $r): \Psr\Http\Message\ResponseInterface
        {
            if ($r->getMethod() === 'POST') {
                $this->posted[] = (string) $r->getUri();

                // Stop the flow once the account registration has been signed and sent
                return $this->factory->createResponse(403)
                    ->withHeader('Content-Type', 'application/problem+json')
                    ->withBody($this->factory->createStream('{"detail":"stop here"}'));
            }

            return $this->factory->createResponse(200)
                ->withHeader('Replay-Nonce', 'nonce')
                ->withBody($this->factory->createStream(json_encode([
                    'newNonce'   => 'https://acme.example/nonce',
                    'newAccount' => 'https://acme.example/new-account',
                    'newOrder'   => 'https://acme.example/new-order',
                ])));
        }
    };

    $coyote = makeCoyote()
        ->httpClient($client, $factory, $factory)
        ->identifiers('example.com')
        ->challenge(makeNoOpHandler())
        ->skipCaaCheck();

    expect(fn() => $coyote->issue())->toThrow(\CoyoteCert\Exceptions\AuthException::class, 'stop here');
    expect($client->posted)->toBe(['https://acme.example/new-account']);
});
