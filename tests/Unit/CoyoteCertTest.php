<?php

use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\LetsEncryptClientException;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Provider\LetsEncryptStaging;
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
        privateKey:  'key-pem',
        fullchain:   'fullchain-pem',
        caBundle:    $caBundle,
        issuedAt:    new DateTimeImmutable(),
        expiresAt:   new DateTimeImmutable("+{$expiresInDays} days"),
        domains:     ['example.com'],
    );
}

function makeNoOpHandler(AuthorizationChallengeEnum $supports = AuthorizationChallengeEnum::HTTP): ChallengeHandlerInterface
{
    return new class ($supports) implements ChallengeHandlerInterface {
        public function __construct(private AuthorizationChallengeEnum $type) {}
        public function supports(AuthorizationChallengeEnum $t): bool { return $t === $this->type; }
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

it('domains() accepts a string', function () {
    $c = makeCoyote();
    expect($c->domains('example.com'))->toBe($c);
});

it('domains() accepts an array', function () {
    $c = makeCoyote();
    expect($c->domains(['example.com', 'www.example.com']))->toBe($c);
});

// ── detectChallengeType() ─────────────────────────────────────────────────────

it('detectChallengeType() throws when the handler supports no known challenge type', function () {
    $noneHandler = new class implements ChallengeHandlerInterface {
        public function supports(AuthorizationChallengeEnum $t): bool { return false; }
        public function deploy(string $d, string $tok, string $auth): void {}
        public function cleanup(string $d, string $tok): void {}
    };

    $coyote = makeCoyote()->challenge($noneHandler);
    $method = new \ReflectionMethod(CoyoteCert::class, 'detectChallengeType');

    expect(fn () => $method->invoke($coyote))
        ->toThrow(LetsEncryptClientException::class, 'does not support any known challenge type');
});

// ── validate() / issue() guard ────────────────────────────────────────────────

it('issue() throws when no domains are configured', function () {
    expect(fn () => makeCoyote()->challenge(makeNoOpHandler())->issue())
        ->toThrow(LetsEncryptClientException::class, 'No domains');
});

it('issue() throws when no challenge handler is configured', function () {
    expect(fn () => makeCoyote()->domains('example.com')->issue())
        ->toThrow(LetsEncryptClientException::class, 'No challenge handler');
});

// ── revoke() guard ────────────────────────────────────────────────────────────

it('revoke() throws when no storage is configured', function () {
    expect(fn () => makeCoyote()->revoke(makeCoyoteCert()))
        ->toThrow(LetsEncryptClientException::class, 'No storage');
});

// ── needsRenewal() ────────────────────────────────────────────────────────────

it('needsRenewal() returns true when no storage is configured', function () {
    expect(makeCoyote()->domains('example.com')->needsRenewal())->toBeTrue();
});

it('needsRenewal() returns true when no certificate is stored', function () {
    $storage = new InMemoryStorage();

    expect(
        makeCoyote()->domains('example.com')->storage($storage)->needsRenewal()
    )->toBeTrue();
});

it('needsRenewal() returns false when certificate has plenty of time remaining', function () {
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(expiresInDays: 90));

    expect(
        makeCoyote()->domains('example.com')->storage($storage)->needsRenewal(30)
    )->toBeFalse();
});

it('needsRenewal() returns true when certificate expires within the threshold', function () {
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(expiresInDays: 10));

    expect(
        makeCoyote()->domains('example.com')->storage($storage)->needsRenewal(30)
    )->toBeTrue();
});

// ── issueOrRenew() ────────────────────────────────────────────────────────────

it('issueOrRenew() returns existing cert when renewal is not needed', function () {
    $storage = new InMemoryStorage();
    $cert    = makeCoyoteCert(expiresInDays: 90);
    $storage->saveCertificate('example.com', $cert);

    $result = makeCoyote()
        ->domains('example.com')
        ->storage($storage)
        ->challenge(makeNoOpHandler())
        ->issueOrRenew(30);

    expect($result->certificate)->toBe('cert-pem');
});

// ── renew() alias ─────────────────────────────────────────────────────────────

it('renew() is an alias for issue() and throws when no domains are configured', function () {
    // renew() delegates to issue() → validate() → throws "No domains"
    expect(fn () => makeCoyote()->challenge(makeNoOpHandler())->renew())
        ->toThrow(LetsEncryptClientException::class, 'No domains');
});

// ── ariWindow() (tested via needsRenewal()) ───────────────────────────────────

it('needsRenewal() falls back to remainingDays when caBundle has no PEM cert headers', function () {
    // caBundle is non-empty but contains no PEM block → ariWindow() returns null at the
    // !preg_match() guard (line 345) → falls through to remainingDays()
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(caBundle: 'not-a-pem', expiresInDays: 90));

    expect(
        makeCoyote()->domains('example.com')->storage($storage)->needsRenewal(30)
    )->toBeFalse();
});

it('needsRenewal() returns null from ariWindow when API call throws (catch block)', function () {
    // caBundle has a valid PEM block → preg_match succeeds → try block reached.
    // A failing HTTP client causes the directory GET to throw → caught → return null.
    $fakeCaBundle = "-----BEGIN CERTIFICATE-----\nMIIBtest==\n-----END CERTIFICATE-----";

    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeCoyoteCert(caBundle: $fakeCaBundle, expiresInDays: 90));

    // PSR-18 client that always throws — forces the try/catch in ariWindow().
    $factory = new \Nyholm\Psr7\Factory\Psr17Factory();
    $failingPsr18 = new class implements \Psr\Http\Client\ClientInterface {
        public function sendRequest(\Psr\Http\Message\RequestInterface $r): \Psr\Http\Message\ResponseInterface {
            throw new \RuntimeException('Connection refused');
        }
    };

    $result = makeCoyote()
        ->httpClient($failingPsr18, $factory, $factory)
        ->domains('example.com')
        ->storage($storage)
        ->needsRenewal(30);

    // ariWindow() returns null (exception caught) → falls back to remainingDays()
    // 90 days > 30 threshold → not needing renewal.
    expect($result)->toBeFalse();
});

it('needsRenewal() returns $window->isOpen() when ARI returns a valid renewal window', function () {
    // Generate a real self-signed cert so certId() can parse it.
    // Use serial=1 so serialNumberHex is always '01' (even-length hex).
    $key  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr  = openssl_csr_new(['commonName' => 'test.example.com'], $key);
    $cert = openssl_csr_sign($csr, null, $key, 365, serial: 1);
    openssl_x509_export($cert, $certPem);

    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', new StoredCertificate(
        certificate: $certPem,
        privateKey:  'key-pem',
        fullchain:   'fullchain',
        caBundle:    $certPem, // self-signed: issuer == leaf
        issuedAt:    new DateTimeImmutable(),
        expiresAt:   new DateTimeImmutable('+90 days'),
        domains:     ['example.com'],
    ));

    $factory   = new \Nyholm\Psr7\Factory\Psr17Factory();
    $callCount = 0;

    $mockClient = new class ($factory, $callCount) implements \Psr\Http\Client\ClientInterface {
        public int $calls = 0;

        public function __construct(private \Nyholm\Psr7\Factory\Psr17Factory $factory, int $_) {}

        public function sendRequest(\Psr\Http\Message\RequestInterface $r): \Psr\Http\Message\ResponseInterface {
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
        ->domains('example.com')
        ->storage($storage)
        ->needsRenewal(30);

    // ARI window is far in the future → isOpen() returns false → no renewal needed
    expect($result)->toBeFalse();
});
