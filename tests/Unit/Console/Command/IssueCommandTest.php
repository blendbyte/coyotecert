<?php

use CoyoteCert\Console\Command\IssueCommand;
use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AuthException;
use CoyoteCert\Exceptions\RateLimitException;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;

use function Termwind\renderUsing;

beforeEach(function () {
    $this->buffer = new BufferedOutput();
    renderUsing($this->buffer);
});

afterEach(function () {
    renderUsing(null);
});

/**
 * Run the IssueCommand and return [statusCode, output].
 * Termwind is redirected to $this->buffer in beforeEach.
 *
 * @return array{0: int, 1: string}
 */
function runIssue(array $input): array
{
    $tester = new CommandTester(new IssueCommand());
    $tester->execute($input);

    return [$tester->getStatusCode(), test()->buffer->fetch()];
}

// ── Input validation ──────────────────────────────────────────────────────────

it('fails when no --identifier is provided', function () {
    [$code, $output] = runIssue([]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('No identifiers specified');
});

it('fails when neither --webroot nor --dns is provided', function () {
    [$code, $output] = runIssue(['--identifier' => ['example.com']]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('--webroot');
});

it('fails when --provider is not provided', function () {
    [$code, $output] = runIssue([
        '--identifier'  => ['example.com'],
        '--webroot' => '/tmp',
    ]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('--provider is required');
});

it('fails for an unknown --provider', function () {
    [$code, $output] = runIssue([
        '--identifier'   => ['example.com'],
        '--webroot'  => '/tmp',
        '--provider' => 'nonexistent-ca',
    ]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('nonexistent-ca');
});

it('fails for an unknown --key-type', function () {
    [$code, $output] = runIssue([
        '--identifier'   => ['example.com'],
        '--webroot'  => '/tmp',
        '--provider' => 'letsencrypt',
        '--key-type' => 'rsa9999',
    ]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('rsa9999');
});

it('fails for google provider without EAB credentials', function () {
    [$code, $output] = runIssue([
        '--identifier'   => ['example.com'],
        '--webroot'  => '/tmp',
        '--provider' => 'google',
    ]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('eab-kid');
});

it('fails for sslcom provider without EAB credentials', function () {
    [$code, $output] = runIssue([
        '--identifier'   => ['example.com'],
        '--webroot'  => '/tmp',
        '--provider' => 'sslcom',
    ]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('eab-kid');
});

// ── Happy path / exception paths (via stub) ───────────────────────────────────

function makeIssueCert(int $daysUntilExpiry = 90, bool $wasIssued = true, KeyType $keyType = KeyType::EC_P256): array
{
    $cert = new StoredCertificate(
        certificate: 'fake-pem',
        privateKey: 'fake-key',
        fullchain: 'fake-fullchain',
        caBundle: 'fake-cabundle',
        issuedAt: new DateTimeImmutable('-1 day'),
        expiresAt: (new DateTimeImmutable())->modify("+{$daysUntilExpiry} days"),
        domains: ['example.com'],
        keyType: $keyType,
    );

    return [$cert, $wasIssued];
}

/**
 * A stub that intercepts performIssue() so no real ACME calls are made.
 * Pass a StoredCertificate (success) or a Throwable (error simulation).
 */
class StubIssueCommand extends IssueCommand
{
    /** @var array{StoredCertificate, bool}|\Throwable */
    private mixed $result;

    public function __construct(mixed $result)
    {
        parent::__construct();
        $this->result = $result;
    }

    protected function performIssue(CoyoteCert $builder, bool $force, int $days): array
    {
        if ($this->result instanceof \Throwable) {
            throw $this->result;
        }

        return $this->result;
    }
}

function runStub(mixed $result, array $input = []): array
{
    $tester = new CommandTester(new StubIssueCommand($result));
    $tester->execute(array_merge([
        '--identifier'   => ['example.com'],
        '--webroot'  => '/tmp',
        '--storage'  => sys_get_temp_dir(),
        '--provider' => 'letsencrypt',
    ], $input));

    return [$tester->getStatusCode(), test()->buffer->fetch()];
}

it('shows success when a certificate is freshly issued', function () {
    [$code, $output] = runStub(makeIssueCert(wasIssued: true));

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('Certificate issued successfully');
    expect($output)->toContain('example.com');
    expect($output)->toContain('days');
});

it('shows no renewal needed when the certificate is still valid', function () {
    [$code, $output] = runStub(makeIssueCert(wasIssued: false));

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('no renewal needed');
});

it('handles a rate limit exception without a retry-after value', function () {
    [$code, $output] = runStub(new RateLimitException('Rate limited', retryAfter: null));

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('Rate limit reached');
    expect($output)->toContain('CA dashboard');
});

it('handles a rate limit exception with a retry-after value in seconds', function () {
    [$code, $output] = runStub(new RateLimitException('Rate limited', retryAfter: 3600));

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('Rate limit reached');
    expect($output)->toContain('3600 seconds');
});

it('handles an auth exception', function () {
    [$code, $output] = runStub(new AuthException('Bad credentials'));

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('Authentication failed');
    expect($output)->toContain('Bad credentials');
});

it('handles a generic throwable', function () {
    [$code, $output] = runStub(new \RuntimeException('Something went wrong'));

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('issuance failed');
    expect($output)->toContain('Something went wrong');
});

it('passes through --email --skip-caa and --skip-local-test without error', function () {
    [$code] = runStub(makeIssueCert(), [
        '--email'           => 'admin@example.com',
        '--skip-caa'        => true,
        '--skip-local-test' => true,
    ]);

    expect($code)->toBe(Command::SUCCESS);
});

it('passes --force to performIssue and succeeds', function () {
    [$code] = runStub(makeIssueCert(), ['--force' => true]);

    expect($code)->toBe(Command::SUCCESS);
});

// ── key type labels in renderSuccess ─────────────────────────────────────────

it('shows EC P-384 key type label in success output', function () {
    [$code, $output] = runStub(
        makeIssueCert(keyType: KeyType::EC_P384),
        ['--key-type' => 'ec384'],
    );

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('EC P-384');
});

it('shows RSA 2048 key type label in success output', function () {
    [$code, $output] = runStub(
        makeIssueCert(keyType: KeyType::RSA_2048),
        ['--key-type' => 'rsa2048'],
    );

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('RSA 2048');
});

it('shows RSA 4096 key type label in success output', function () {
    [$code, $output] = runStub(
        makeIssueCert(keyType: KeyType::RSA_4096),
        ['--key-type' => 'rsa4096'],
    );

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('RSA 4096');
});

// ── expiry colour branches in renderSuccess ───────────────────────────────────

it('uses warning colour when certificate expires within 7 days', function () {
    [$code] = runStub(makeIssueCert(daysUntilExpiry: 5));

    expect($code)->toBe(Command::SUCCESS);
});

it('uses caution colour when certificate expires within 30 days', function () {
    [$code] = runStub(makeIssueCert(daysUntilExpiry: 20));

    expect($code)->toBe(Command::SUCCESS);
});

// ── DNS provider resolution ───────────────────────────────────────────────────

afterEach(function () {
    putenv('DNS_DEPLOY_CMD');
});

it('fails for an unknown --dns provider', function () {
    [$code, $output] = runStub(makeIssueCert(), ['--dns' => 'unknown-provider']);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('unknown-provider');
});

it('fails when the required env var is missing for the --dns provider', function () {
    putenv('DNS_DEPLOY_CMD');

    [$code, $output] = runStub(makeIssueCert(), ['--dns' => 'exec']);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('DNS_DEPLOY_CMD');
});

it('resolves the --dns exec handler and succeeds when the env var is set', function () {
    putenv('DNS_DEPLOY_CMD=echo');

    [$code] = runStub(makeIssueCert(), ['--dns' => 'exec']);

    expect($code)->toBe(Command::SUCCESS);
});

it('applies --dns-propagation-timeout when provided', function () {
    putenv('DNS_DEPLOY_CMD=echo');

    [$code] = runStub(makeIssueCert(), ['--dns' => 'exec', '--dns-propagation-timeout' => '120']);

    expect($code)->toBe(Command::SUCCESS);
});

it('applies --dns-propagation-delay when provided', function () {
    putenv('DNS_DEPLOY_CMD=echo');

    [$code] = runStub(makeIssueCert(), ['--dns' => 'exec', '--dns-propagation-delay' => '5']);

    expect($code)->toBe(Command::SUCCESS);
});

it('applies --dns-skip-propagation when provided', function () {
    putenv('DNS_DEPLOY_CMD=echo');

    [$code] = runStub(makeIssueCert(), ['--dns' => 'exec', '--dns-skip-propagation' => true]);

    expect($code)->toBe(Command::SUCCESS);
});
