<?php

use CoyoteCert\Console\Command\CertsCommand;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

beforeEach(function () {
    $this->dir     = sys_get_temp_dir() . '/coyote-list-test-' . uniqid();
    $this->storage = new FilesystemStorage($this->dir);
    $this->tester  = new CommandTester(new CertsCommand());
});

afterEach(function () {
    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }
});

function makeListCert(
    int $daysUntilExpiry = 90,
    KeyType $keyType = KeyType::EC_P256,
    array $domains = ['example.com'],
): StoredCertificate {
    $expiresAt = (new DateTimeImmutable())->modify("+{$daysUntilExpiry} days");

    return new StoredCertificate(
        certificate: 'fake-pem',
        privateKey: 'fake-key',
        fullchain: 'fake-fullchain',
        caBundle: 'fake-cabundle',
        issuedAt: $expiresAt->modify('-90 days'),
        expiresAt: $expiresAt,
        domains: $domains,
        keyType: $keyType,
    );
}

// ── Input validation ──────────────────────────────────────────────────────────

it('fails when the storage directory does not exist', function () {
    $this->tester->execute(['--storage' => '/nonexistent/path/xyz']);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::FAILURE);
    expect($output)->toContain('Storage directory not found');
});

// ── Empty storage ─────────────────────────────────────────────────────────────

it('reports no certificates when the directory is empty', function () {
    mkdir($this->dir);

    $this->tester->execute(['--storage' => $this->dir]);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::SUCCESS);
    expect($output)->toContain('No certificates found');
});

// ── Happy path ────────────────────────────────────────────────────────────────

it('lists a single certificate', function () {
    $this->storage->saveCertificate('example.com', makeListCert());

    $this->tester->execute(['--storage' => $this->dir]);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::SUCCESS);
    expect($output)->toContain('example.com');
    expect($output)->toContain('1 certificate');
});

it('lists multiple certificates and shows the count', function () {
    $this->storage->saveCertificate('alpha.com', makeListCert(domains: ['alpha.com']));
    $this->storage->saveCertificate('beta.com', makeListCert(domains: ['beta.com']));
    $this->storage->saveCertificate('gamma.com', makeListCert(domains: ['gamma.com']));

    $this->tester->execute(['--storage' => $this->dir]);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::SUCCESS);
    expect($output)->toContain('alpha.com');
    expect($output)->toContain('beta.com');
    expect($output)->toContain('gamma.com');
    expect($output)->toContain('3 certificates');
});

it('shows all domains for a multi-domain certificate', function () {
    $cert = makeListCert(domains: ['example.com', 'www.example.com', 'api.example.com']);
    $this->storage->saveCertificate('example.com', $cert);

    $this->tester->execute(['--storage' => $this->dir]);

    $output = $this->tester->getDisplay();

    expect($output)->toContain('www.example.com');
    expect($output)->toContain('api.example.com');
});

// ── Status labels ─────────────────────────────────────────────────────────────

it('shows Valid status for a certificate with plenty of time remaining', function () {
    $this->storage->saveCertificate('example.com', makeListCert(daysUntilExpiry: 90));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('Valid');
});

it('shows Renewal due when between 7 and 30 days remain', function () {
    $this->storage->saveCertificate('example.com', makeListCert(daysUntilExpiry: 20));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('Renewal due');
});

it('shows Expiring soon when fewer than 7 days remain', function () {
    $this->storage->saveCertificate('example.com', makeListCert(daysUntilExpiry: 3));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('Expiring soon');
});

it('shows Expired for a past-expiry certificate', function () {
    $expired = new StoredCertificate(
        certificate: 'fake-pem',
        privateKey: 'fake-key',
        fullchain: '',
        caBundle: '',
        issuedAt: new DateTimeImmutable('-100 days'),
        expiresAt: new DateTimeImmutable('-1 day'),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    );
    $this->storage->saveCertificate('example.com', $expired);

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('Expired');
});

// ── Key type labels ───────────────────────────────────────────────────────────

it('shows the EC P-256 key type label', function () {
    $this->storage->saveCertificate('example.com', makeListCert(keyType: KeyType::EC_P256));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('EC P-256');
});

it('shows the EC P-384 key type label', function () {
    $this->storage->saveCertificate('example.com', makeListCert(keyType: KeyType::EC_P384));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('EC P-384');
});

it('shows the RSA 2048 key type label', function () {
    $this->storage->saveCertificate('example.com', makeListCert(keyType: KeyType::RSA_2048));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('RSA 2048');
});

it('shows the RSA 4096 key type label', function () {
    $this->storage->saveCertificate('example.com', makeListCert(keyType: KeyType::RSA_4096));

    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getDisplay())->toContain('RSA 4096');
});

// ── Filesystem edge cases ─────────────────────────────────────────────────────

it('ignores cert files with an unrecognised key type in the filename', function () {
    mkdir($this->dir, 0o700, true);
    // A file that matches *.cert.json but has no valid key type in its name.
    file_put_contents($this->dir . '/example.com.cert.json', '{}');

    $this->tester->execute(['--storage' => $this->dir]);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::SUCCESS);
    expect($output)->toContain('No certificates found');
});

// ── Sorting ───────────────────────────────────────────────────────────────────

it('sorts certificates by expiry date ascending', function () {
    $this->storage->saveCertificate('far.com', makeListCert(daysUntilExpiry: 300, domains: ['far.com']));
    $this->storage->saveCertificate('near.com', makeListCert(daysUntilExpiry: 10, domains: ['near.com']));
    $this->storage->saveCertificate('mid.com', makeListCert(daysUntilExpiry: 60, domains: ['mid.com']));

    $this->tester->execute(['--storage' => $this->dir]);

    $output = $this->tester->getDisplay();

    expect(strpos($output, 'near.com'))->toBeLessThan(strpos($output, 'mid.com'));
    expect(strpos($output, 'mid.com'))->toBeLessThan(strpos($output, 'far.com'));
});
