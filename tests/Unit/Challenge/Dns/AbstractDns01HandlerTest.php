<?php

use CoyoteCert\Challenge\Dns\AbstractDns01Handler;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\DomainValidationException;

// Concrete subclass for testing the abstract base.
// Overrides pollForTxtRecord() so tests never make real DNS queries.
class TestDns01Handler extends AbstractDns01Handler
{
    public array $deployed  = [];
    public array $cleaned   = [];
    public int   $pollCalls = 0;

    /** When set, pollForTxtRecord() throws DomainValidationException on every call. */
    public bool $pollAlwaysFails = false;

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->deployed[] = compact('domain', 'token', 'keyAuthorization');
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        $this->cleaned[] = compact('domain', 'token');
    }

    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void
    {
        $this->pollCalls++;

        if ($this->pollAlwaysFails) {
            throw DomainValidationException::localDnsChallengeTestFailed($domain);
        }
    }
}

// ── Challenge type dispatch ───────────────────────────────────────────────────

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

// ── challengeName ─────────────────────────────────────────────────────────────

it('challengeName prepends _acme-challenge', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $d, string $t, string $k): void {}
        public function cleanup(string $d, string $t): void {}
        public function name(string $domain): string
        {
            return $this->challengeName($domain);
        }
    };

    expect($handler->name('example.com'))->toBe('_acme-challenge.example.com');
    expect($handler->name('sub.example.com'))->toBe('_acme-challenge.sub.example.com');
});

// ── Fluent builder immutability ───────────────────────────────────────────────

it('skipPropagationCheck returns a new immutable instance', function () {
    $original = new TestDns01Handler();
    $disabled = $original->skipPropagationCheck();

    expect($disabled)->not->toBe($original);
    expect($disabled)->toBeInstanceOf(TestDns01Handler::class);
});

it('propagationTimeout returns a new immutable instance', function () {
    $original = new TestDns01Handler();
    $longer   = $original->propagationTimeout(120);

    expect($longer)->not->toBe($original);
    expect($longer)->toBeInstanceOf(TestDns01Handler::class);
});

it('propagationDelay returns a new immutable instance', function () {
    $original = new TestDns01Handler();
    $delayed  = $original->propagationDelay(5);

    expect($delayed)->not->toBe($original);
    expect($delayed)->toBeInstanceOf(TestDns01Handler::class);
});

it('propagationDelay clamps negative values to zero', function () {
    $handler = (new TestDns01Handler())->propagationDelay(-10);
    expect(fn() => $handler->deploy('example.com', 't', 'k'))->not->toThrow(\Throwable::class);
});

it('propagationTimeout clamps zero and negative values to one', function () {
    $prop = new ReflectionProperty(AbstractDns01Handler::class, 'propagationTimeout');

    expect($prop->getValue((new TestDns01Handler())->propagationTimeout(0)))->toBe(1);
    expect($prop->getValue((new TestDns01Handler())->propagationTimeout(-5)))->toBe(1);
    expect($prop->getValue((new TestDns01Handler())->propagationTimeout(30)))->toBe(30);
});

// ── DNS propagation check ─────────────────────────────────────────────────────

it('pollForTxtRecord is called by default after deploy', function () {
    $handler = new TestDns01Handler();
    $handler->deploy('example.com', 'tok', 'keyauth');

    expect($handler->pollCalls)->toBe(1);
});

it('skipPropagationCheck prevents pollForTxtRecord from being called', function () {
    $handler = (new TestDns01Handler())->skipPropagationCheck();
    $handler->deploy('example.com', 'tok', 'keyauth');

    expect($handler->pollCalls)->toBe(0);
});

it('awaitPropagation fails open when poll always fails (timeout reached)', function () {
    $handler                  = new TestDns01Handler();
    $handler->pollAlwaysFails = true;

    // Should not throw even though pollForTxtRecord always fails
    expect(fn() => $handler->deploy('example.com', 'tok', 'keyauth'))->not->toThrow(\Throwable::class);
});

// ── deploy / cleanup arguments ────────────────────────────────────────────────

it('deploy and cleanup record their arguments', function () {
    $handler = new TestDns01Handler();
    $handler->deploy('example.com', 'tok', 'keyauth-value');
    $handler->cleanup('example.com', 'tok');

    expect($handler->deployed[0])->toBe(['domain' => 'example.com', 'token' => 'tok', 'keyAuthorization' => 'keyauth-value']);
    expect($handler->cleaned[0])->toBe(['domain' => 'example.com', 'token' => 'tok']);
});
