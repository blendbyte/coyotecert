<?php

declare(strict_types=1);

use CoyoteCert\Challenge\Dns\ShellDns01Handler;
use CoyoteCert\Exceptions\ChallengeException;

/**
 * Captures run() calls without executing a real process.
 * Overrides pollForTxtRecords() so awaitPropagation() is a no-op.
 */
class MockShellHandler extends ShellDns01Handler
{
    /** @var list<array{cmdTemplate: string, domain: string, keyAuth: string}> */
    public array $calls = [];

    protected function run(string $cmdTemplate, string $domain, string $keyAuth): void
    {
        $this->calls[] = compact('cmdTemplate', 'domain', 'keyAuth');
    }

    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
}

/**
 * Uses the real run() + proc_open, but skips the DNS propagation check.
 */
class ShellHandlerWithRealRun extends ShellDns01Handler
{
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void {}
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

it('cleanup runs once per deployed value so the hook can remove exactly that value', function () {
    $handler = new MockShellHandler('/hook add {domain} {keyauth}', '/hook del {domain} {keyauth}');
    $handler->deploy('example.com', '', 'base-value');
    $handler->deploy('example.com', '', 'wildcard-value');
    $handler->cleanup('example.com', '_acme-challenge');
    $handler->cleanup('example.com', '_acme-challenge'); // second identifier: already cleaned

    $cleanups = array_values(array_filter($handler->calls, fn($c) => str_contains($c['cmdTemplate'], 'del')));
    expect(array_column($cleanups, 'keyAuth'))->toBe(['base-value', 'wildcard-value']);
});

it('run() does not deadlock when the command writes a lot to stderr', function () {
    $php     = escapeshellarg(PHP_BINARY);
    $handler = new ShellHandlerWithRealRun($php . ' -r ' . escapeshellarg('fwrite(STDERR, str_repeat("x", 200000)); echo str_repeat("y", 200000); exit(3);'));

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'exited with code 3: xxx');
});

it('run() stops a command that runs longer than the timeout', function () {
    $handler = new ShellHandlerWithRealRun('sleep 5', timeout: 1);
    $start   = microtime(true);

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'did not finish within 1 seconds');
    expect(microtime(true) - $start)->toBeLessThan(4);
});
