<?php

use CoyoteCert\Console\Command\RevokeCommand;
use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Enums\RevocationReason;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\AuthException;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

beforeEach(function () {
    $this->dir     = sys_get_temp_dir() . '/coyote-revoke-test-' . uniqid();
    $this->storage = new FilesystemStorage($this->dir);
});

afterEach(function () {
    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }
});

function makeRevokeCert(
    KeyType $keyType = KeyType::EC_P256,
    array $domains = ['example.com'],
): StoredCertificate {
    return new StoredCertificate(
        certificate: 'fake-pem',
        privateKey: 'fake-key',
        fullchain: 'fake-fullchain',
        caBundle: 'fake-cabundle',
        issuedAt: new DateTimeImmutable('-30 days'),
        expiresAt: (new DateTimeImmutable())->modify('+60 days'),
        domains: $domains,
        keyType: $keyType,
    );
}

/**
 * A stub that intercepts performRevoke() so no real ACME calls are made.
 * Pass null for success or a Throwable to simulate an error.
 */
class StubRevokeCommand extends RevokeCommand
{
    private ?\Throwable $error;

    public function __construct(?\Throwable $error = null)
    {
        parent::__construct();
        $this->error = $error;
    }

    protected function performRevoke(CoyoteCert $coyote, StoredCertificate $cert, RevocationReason $reason): void
    {
        if ($this->error !== null) {
            throw $this->error;
        }
    }
}

function runRevoke(array $input, ?\Throwable $stubError = null): array
{
    $tester = new CommandTester(new StubRevokeCommand($stubError));
    $tester->execute($input);

    return [$tester->getStatusCode(), $tester->getDisplay()];
}

// ── Input validation ──────────────────────────────────────────────────────────

it('fails when --identifier is not provided', function () {
    [$code, $output] = runRevoke(['--provider' => 'letsencrypt']);

    expect($code)->toBe(Command::INVALID);
    expect($output)->toContain('--identifier is required');
});

it('fails when --provider is not provided', function () {
    [$code, $output] = runRevoke(['--identifier' => 'example.com']);

    expect($code)->toBe(Command::INVALID);
    expect($output)->toContain('--provider is required');
});

it('fails for an unknown --provider', function () {
    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'nonexistent-ca',
    ]);

    expect($code)->toBe(Command::INVALID);
    expect($output)->toContain('nonexistent-ca');
});

it('fails for an unknown --key-type', function () {
    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--key-type'   => 'rsa9999',
    ]);

    expect($code)->toBe(Command::INVALID);
    expect($output)->toContain('rsa9999');
});

it('fails for an unknown --reason', function () {
    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--reason'     => 'notareason',
    ]);

    expect($code)->toBe(Command::INVALID);
    expect($output)->toContain('notareason');
});

it('does not need EAB credentials to revoke with an EAB provider', function () {
    // Revocation is signed with the stored account key; EAB is only used to register an account
    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'google',
        '--storage'    => $this->dir,
    ]);

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('No certificate found')->not->toContain('eab');
});

it('fails when no certificate is found in storage', function () {
    $tester = new CommandTester(new StubRevokeCommand());
    $tester->execute([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ]);

    $output = $tester->getDisplay();

    expect($tester->getStatusCode())->toBe(Command::FAILURE);
    expect($output)->toContain('No certificate found');
    expect($output)->toContain('example.com');
});

// ── Happy path ────────────────────────────────────────────────────────────────

it('shows success after revocation', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ]);

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('Certificate revoked');
    expect($output)->toContain('example.com');
});

it('shows the revocation reason in the output', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
        '--reason'     => 'keycompromise',
    ]);

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('KeyCompromise');
});

it('defaults to Unspecified reason when --reason is not provided', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ]);

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain('Unspecified');
});

it('shows the provider display name in the output', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ]);

    expect($code)->toBe(Command::SUCCESS);
    expect($output)->toContain("Let's Encrypt");
});

it('accepts all valid key types', function (string $keyTypeStr, KeyType $keyType) {
    $this->storage->saveCertificate('example.com', makeRevokeCert(keyType: $keyType));

    [$code] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
        '--key-type'   => $keyTypeStr,
    ]);

    expect($code)->toBe(Command::SUCCESS);
})->with([
    ['ec256',   KeyType::EC_P256],
    ['ec384',   KeyType::EC_P384],
    ['rsa2048', KeyType::RSA_2048],
    ['rsa4096', KeyType::RSA_4096],
]);

it('performRevoke delegates to CoyoteCert::revoke and surfaces the AcmeException', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    $tester = new CommandTester(new RevokeCommand());
    $tester->execute([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ]);

    $output = $tester->getDisplay();

    // The fake cert PEM triggers AcmeException('Could not parse the certificate.')
    // inside Certificate::revoke() before any network call is made.
    expect($tester->getStatusCode())->toBe(Command::FAILURE);
    expect($output)->toContain('Revocation failed');
    expect($output)->toContain('Could not parse the certificate');
});

// ── Exception handling ────────────────────────────────────────────────────────

it('handles an auth exception', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ], new AuthException('Bad credentials'));

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('Authentication failed');
    expect($output)->toContain('Bad credentials');
});

it('handles a generic ACME exception', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ], new AcmeException('CA rejected the request'));

    expect($code)->toBe(Command::FAILURE);
    expect($output)->toContain('Revocation failed');
    expect($output)->toContain('CA rejected the request');
});

// ── Reason resolution ─────────────────────────────────────────────────────────

it('accepts all valid reason strings', function (string $reason) {
    $this->storage->saveCertificate('example.com', makeRevokeCert());

    [$code] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
        '--reason'     => $reason,
    ]);

    expect($code)->toBe(Command::SUCCESS);
})->with([
    'unspecified',
    'keycompromise',
    'cacompromise',
    'affiliationchanged',
    'superseded',
    'cessationofoperation',
    'certificatehold',
    'privilegewithdrawn',
    'aacompromise',
]);

it('asks for --key-type when several certificates are stored for the identifier', function () {
    $this->storage->saveCertificate('example.com', makeRevokeCert(KeyType::EC_P256));
    $this->storage->saveCertificate('example.com', makeRevokeCert(KeyType::RSA_2048));

    [$code, $output] = runRevoke([
        '--identifier' => 'example.com',
        '--provider'   => 'letsencrypt',
        '--storage'    => $this->dir,
    ]);

    expect($code)->toBe(Command::INVALID);
    expect($output)->toContain('Choose one with --key-type');
});
