<?php

use CoyoteCert\Challenge\DnsPersist01Handler;
use CoyoteCert\Enums\AuthorizationChallengeEnum;

// Concrete subclass for testing the abstract base
class TestDnsPersist01Handler extends DnsPersist01Handler
{
    public array $deployed = [];

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->deployed[] = compact('domain', 'token', 'keyAuthorization');
    }
}

it('supports the dns-persist-01 challenge type', function () {
    $handler = new TestDnsPersist01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::DNS_PERSIST))->toBeTrue();
});

it('does not support http-01', function () {
    $handler = new TestDnsPersist01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::HTTP))->toBeFalse();
});

it('does not support dns-01', function () {
    $handler = new TestDnsPersist01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::DNS))->toBeFalse();
});

it('deploy is called and records the arguments', function () {
    $handler = new TestDnsPersist01Handler();
    $handler->deploy('example.com', 'tok', 'keyauth-value');

    expect($handler->deployed)->toHaveCount(1);
    expect($handler->deployed[0]['domain'])->toBe('example.com');
    expect($handler->deployed[0]['token'])->toBe('tok');
    expect($handler->deployed[0]['keyAuthorization'])->toBe('keyauth-value');
});

it('cleanup is a no-op and does not throw', function () {
    $handler = new TestDnsPersist01Handler();
    $handler->deploy('example.com', 'tok', 'keyauth');

    expect(fn() => $handler->cleanup('example.com', 'tok'))->not->toThrow(\Throwable::class);
});

it('deploy array is unchanged after cleanup', function () {
    $handler = new TestDnsPersist01Handler();
    $handler->deploy('example.com', 'tok', 'val');
    $handler->cleanup('example.com', 'tok');

    // cleanup is a no-op — the "record" stays deployed
    expect($handler->deployed)->toHaveCount(1);
});
