<?php

use CoyoteCert\Challenge\Dns\AbstractDns01Handler;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\DomainValidationException;

afterEach(function () {
    unset($GLOBALS['__test_time']);
});

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

// ── zoneCandidates ────────────────────────────────────────────────────────────

it('zoneCandidates returns just the apex for a two-part domain', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $d, string $t, string $k): void {}
        public function cleanup(string $d, string $t): void {}
        public function candidates(string $domain): array { return $this->zoneCandidates($domain); }
    };

    expect($handler->candidates('example.com'))->toBe(['example.com']);
});

it('zoneCandidates produces the full suffix walk for a subdomain', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $d, string $t, string $k): void {}
        public function cleanup(string $d, string $t): void {}
        public function candidates(string $domain): array { return $this->zoneCandidates($domain); }
    };

    expect($handler->candidates('sub.example.com'))->toBe(['sub.example.com', 'example.com']);
});

// ── relativeRecordName ────────────────────────────────────────────────────────

it('relativeRecordName returns _acme-challenge for an apex domain', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $d, string $t, string $k): void {}
        public function cleanup(string $d, string $t): void {}
        public function name(string $domain, string $zone): string { return $this->relativeRecordName($domain, $zone); }
    };

    expect($handler->name('example.com', 'example.com'))->toBe('_acme-challenge');
});

it('relativeRecordName returns _acme-challenge.sub for a one-level subdomain', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $d, string $t, string $k): void {}
        public function cleanup(string $d, string $t): void {}
        public function name(string $domain, string $zone): string { return $this->relativeRecordName($domain, $zone); }
    };

    expect($handler->name('sub.example.com', 'example.com'))->toBe('_acme-challenge.sub');
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

it('propagationDelay executes the sleep branch when the delay is positive', function () {
    $handler = (new TestDns01Handler())->propagationDelay(5);
    $handler->deploy('example.com', 'tok', 'keyauth');

    // sleep() is a no-op in the test namespace — verifies the branch runs cleanly.
    expect($handler->deployed)->toHaveCount(1);
});

it('real pollForTxtRecord fails open when the DNS lookup cannot be satisfied', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $domain, string $token, string $keyAuth): void
        {
            $this->awaitPropagation($domain, $keyAuth);
        }

        public function cleanup(string $domain, string $token): void {}
    };

    // Does not override pollForTxtRecord() — exercises the real implementation.
    // DNS fails for .invalid; propagationTimeout(1) keeps the poll window short.
    // Fails open: no exception is thrown when the timeout is reached.
    expect(
        fn() => $handler->propagationTimeout(1)->deploy('test.invalid', '', 'no-such-record'),
    )->not->toThrow(\Throwable::class);
});

it('pollForTxtRecord returns immediately when isTxtRecordVisible returns true', function () {
    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $domain, string $token, string $keyAuth): void
        {
            $this->awaitPropagation($domain, $keyAuth);
        }

        public function cleanup(string $domain, string $token): void {}

        protected function isTxtRecordVisible(string $domain, string $keyAuthorization): bool
        {
            return true;
        }
    };

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))->not->toThrow(\Throwable::class);
});

it('pollForTxtRecord sleeps between poll attempts when the deadline has not passed', function () {
    // Freeze fake time so the deadline check is deterministic regardless of real DNS speed.
    // sleep() in this namespace advances __test_time, so after sleep(5) the fake clock
    // reads start+5, which is past the start+1 deadline — loop exits after one sleep call.
    $GLOBALS['__test_time'] = \time();

    $handler = new class extends AbstractDns01Handler {
        public function deploy(string $domain, string $token, string $keyAuth): void
        {
            $this->awaitPropagation($domain, $keyAuth);
        }

        public function cleanup(string $domain, string $token): void {}
    };

    expect(
        fn() => $handler->propagationTimeout(1)->deploy('test.invalid', '', 'no-such-record'),
    )->not->toThrow(\Throwable::class);
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
