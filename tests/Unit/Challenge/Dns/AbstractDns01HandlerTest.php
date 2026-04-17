<?php

use CoyoteCert\Challenge\Dns\AbstractDns01Handler;
use CoyoteCert\Enums\AuthorizationChallengeEnum;

// Minimal concrete subclass for testing the abstract base
class TestDns01Handler extends AbstractDns01Handler
{
    public array $deployed = [];
    public array $cleaned  = [];

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->deployed[] = compact('domain', 'token', 'keyAuthorization');
        $this->sleepForPropagation();
    }

    public function cleanup(string $domain, string $token): void
    {
        $this->cleaned[] = compact('domain', 'token');
    }
}

it('supports the dns-01 challenge type', function () {
    expect((new TestDns01Handler())->supports(AuthorizationChallengeEnum::DNS))->toBeTrue();
});

it('does not support http-01', function () {
    expect((new TestDns01Handler())->supports(AuthorizationChallengeEnum::HTTP))->toBeFalse();
});

it('does not support dns-persist-01', function () {
    expect((new TestDns01Handler())->supports(AuthorizationChallengeEnum::DNS_PERSIST))->toBeFalse();
});

it('does not support tls-alpn-01', function () {
    expect((new TestDns01Handler())->supports(AuthorizationChallengeEnum::TLS_ALPN))->toBeFalse();
});

it('challengeName prepends _acme-challenge', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $d, string $t, string $k): void {}
        public function cleanup(string $d, string $t): void {}
        public function name(string $domain): string { return $this->challengeName($domain); }
    };

    expect($handler->name('example.com'))->toBe('_acme-challenge.example.com');
    expect($handler->name('sub.example.com'))->toBe('_acme-challenge.sub.example.com');
});

it('propagationDelay returns a new immutable instance', function () {
    $original = new TestDns01Handler();
    $delayed  = $original->propagationDelay(5);

    expect($delayed)->not->toBe($original);
    expect($delayed)->toBeInstanceOf(TestDns01Handler::class);
});

it('propagationDelay clamps negative values to zero', function () {
    // Negative delays should not cause a sleep — verify no exception is thrown
    $handler = (new TestDns01Handler())->propagationDelay(-10);
    expect(fn () => $handler->deploy('example.com', 't', 'k'))->not->toThrow(\Throwable::class);
});

it('deploy and cleanup record their arguments', function () {
    $handler = new TestDns01Handler();
    $handler->deploy('example.com', 'tok', 'keyauth-value');
    $handler->cleanup('example.com', 'tok');

    expect($handler->deployed[0])->toBe(['domain' => 'example.com', 'token' => 'tok', 'keyAuthorization' => 'keyauth-value']);
    expect($handler->cleaned[0])->toBe(['domain' => 'example.com', 'token' => 'tok']);
});
