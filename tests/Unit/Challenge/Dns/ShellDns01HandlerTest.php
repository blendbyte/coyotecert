<?php

use CoyoteCert\Challenge\Dns\ShellDns01Handler;
use CoyoteCert\Exceptions\ChallengeException;

/**
 * Captures run() calls without executing a real process.
 * Overrides pollForTxtRecord() so awaitPropagation() is a no-op.
 */
class MockShellHandler extends ShellDns01Handler
{
    /** @var list<array{cmdTemplate: string, domain: string, keyAuth: string}> */
    public array $calls = [];

    protected function run(string $cmdTemplate, string $domain, string $keyAuth): void
    {
        $this->calls[] = compact('cmdTemplate', 'domain', 'keyAuth');
    }

    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

/**
 * Uses the real run() + proc_open, but skips the DNS propagation check.
 */
class ShellHandlerWithRealRun extends ShellDns01Handler
{
    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

// ── deploy() routing ──────────────────────────────────────────────────────────

it('deploy passes the deploy command template to run()', function () {
    $handler = new MockShellHandler('/hook {domain} {keyauth}');
    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->calls[0]['cmdTemplate'])->toBe('/hook {domain} {keyauth}');
});

it('deploy passes domain and keyAuthorization to run()', function () {
    $handler = new MockShellHandler('/hook {domain} {keyauth}');
    $handler->deploy('example.com', '', 'my-key-auth');

    expect($handler->calls[0]['domain'])->toBe('example.com');
    expect($handler->calls[0]['keyAuth'])->toBe('my-key-auth');
});

// ── cleanup() routing ─────────────────────────────────────────────────────────

it('cleanup is a no-op when no cleanup command is provided', function () {
    $handler = new MockShellHandler('/hook {domain} {keyauth}');
    $handler->cleanup('example.com', '');

    expect($handler->calls)->toBeEmpty();
});

it('cleanup passes the cleanup command template to run()', function () {
    $handler = new MockShellHandler('/hook add {domain} {keyauth}', '/hook del {domain}');
    $handler->cleanup('example.com', '');

    expect($handler->calls[0]['cmdTemplate'])->toBe('/hook del {domain}');
    expect($handler->calls[0]['domain'])->toBe('example.com');
    expect($handler->calls[0]['keyAuth'])->toBe('');
});

afterEach(function () {
    unset($GLOBALS['__test_proc_open']);
});

// ── proc_open failure ─────────────────────────────────────────────────────────

it('run() throws ChallengeException when proc_open fails to start the process', function () {
    $GLOBALS['__test_proc_open'] = false;
    $handler                     = new ShellHandlerWithRealRun('/some-command {domain}');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'failed to start');
});

// ── run() via real shell ──────────────────────────────────────────────────────

it('run() does not throw when the command exits with code 0', function () {
    $handler = new ShellHandlerWithRealRun('true');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->not->toThrow(\Throwable::class);
});

it('run() throws ChallengeException when the command exits with a non-zero code', function () {
    $handler = new ShellHandlerWithRealRun('false');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'exited with code');
});

it('run() substitutes {domain} in the command', function () {
    // sh -c 'test "$1" = value' -- {domain} exits 0 on match, 1 on mismatch.
    $handler = new ShellHandlerWithRealRun("sh -c 'test \"\$1\" = example.com' -- {domain}");

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->not->toThrow(\Throwable::class);
});

it('run() substitutes {keyauth} in the command', function () {
    $handler = new ShellHandlerWithRealRun("sh -c 'test \"\$1\" = my-key-auth' -- {keyauth}");

    expect(fn() => $handler->deploy('example.com', '', 'my-key-auth'))
        ->not->toThrow(\Throwable::class);
});

it('run() sets ACME_DOMAIN in the child process environment', function () {
    $handler = new ShellHandlerWithRealRun("sh -c 'test \"\$ACME_DOMAIN\" = example.com'");

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->not->toThrow(\Throwable::class);
});

it('run() sets ACME_KEYAUTH in the child process environment', function () {
    $handler = new ShellHandlerWithRealRun("sh -c 'test \"\$ACME_KEYAUTH\" = my-key-auth'");

    expect(fn() => $handler->deploy('example.com', '', 'my-key-auth'))
        ->not->toThrow(\Throwable::class);
});
