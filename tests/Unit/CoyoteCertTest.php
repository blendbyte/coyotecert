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
