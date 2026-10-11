<?php

use CoyoteCert\Console\Command\StatusCommand;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

beforeEach(function () {
    $this->dir     = sys_get_temp_dir() . '/coyote-status-test-' . uniqid();
    $this->storage = new FilesystemStorage($this->dir);
    $this->tester  = new CommandTester(new StatusCommand());
});

afterEach(function () {
    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }
});

function makeStatusCert(
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

it('fails when --identifier is not provided', function () {
    $this->tester->execute(['--storage' => $this->dir]);

    expect($this->tester->getStatusCode())->toBe(Command::INVALID);
    expect($this->tester->getDisplay())->toContain('--identifier is required');
});

it('fails when no certificate is found in storage', function () {
    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::FAILURE);
    expect($output)->toContain('No certificate found');
    expect($output)->toContain('example.com');
});

it('fails for an unknown --key-type', function () {
    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
        '--key-type'   => 'rsa9999',
    ]);

    expect($this->tester->getStatusCode())->toBe(Command::INVALID);
    expect($this->tester->getDisplay())->toContain('rsa9999');
});

// ── Happy path ────────────────────────────────────────────────────────────────

it('shows cert details for a valid certificate', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(daysUntilExpiry: 90));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    $output = $this->tester->getDisplay();

    expect($this->tester->getStatusCode())->toBe(Command::SUCCESS);
    expect($output)->toContain('example.com');
    expect($output)->toContain('Valid');
});

it('shows days remaining', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(daysUntilExpiry: 45));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    expect($this->tester->getDisplay())->toContain('days remaining');
});

it('shows Expiring soon when fewer than 7 days remain', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(daysUntilExpiry: 5));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    expect($this->tester->getDisplay())->toContain('Expiring soon');
});

it('shows Renewal due when between 7 and 30 days remain', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(daysUntilExpiry: 20));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    expect($this->tester->getDisplay())->toContain('Renewal due');
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

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    expect($this->tester->getDisplay())->toContain('Expired');
});

it('shows the key type label', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(keyType: KeyType::RSA_2048));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
        '--key-type'   => 'rsa2048',
    ]);

    expect($this->tester->getDisplay())->toContain('RSA 2048');
});

it('shows all domains for a multi-domain certificate', function () {
    $cert = makeStatusCert(domains: ['example.com', 'www.example.com', 'api.example.com']);
    $this->storage->saveCertificate('example.com', $cert);

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    $output = $this->tester->getDisplay();

    expect($output)->toContain('www.example.com');
    expect($output)->toContain('api.example.com');
});

it('shows the EC P-384 key type label', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(keyType: KeyType::EC_P384));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
        '--key-type'   => 'ec384',
    ]);

    expect($this->tester->getDisplay())->toContain('EC P-384');
});

it('shows the RSA 4096 key type label', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(keyType: KeyType::RSA_4096));

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
        '--key-type'   => 'rsa4096',
    ]);

    expect($this->tester->getDisplay())->toContain('RSA 4096');
});

it('shows SANs parsed from a real certificate', function () {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'example.com'], $key);

    $configFile = tempnam(sys_get_temp_dir(), 'openssl-') . '.cnf';
    file_put_contents($configFile, implode("\n", [
        '[req]',
        'distinguished_name = req_distinguished_name',
        '[req_distinguished_name]',
        '[v3_req]',
        'subjectAltName = DNS:example.com, DNS:www.example.com',
    ]));

    $selfSignedCert = openssl_csr_sign($csr, null, $key, 30, [
        'config'          => $configFile,
        'x509_extensions' => 'v3_req',
        'digest_alg'      => 'sha256',
    ]);

    $pem = '';
    openssl_x509_export($selfSignedCert, $pem);
    unlink($configFile);

    $stored = new StoredCertificate(
        certificate: $pem,
        privateKey: 'fake-key',
        fullchain: $pem,
        caBundle: '',
        issuedAt: new DateTimeImmutable('-1 day'),
        expiresAt: (new DateTimeImmutable())->modify('+90 days'),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    );
    $this->storage->saveCertificate('example.com', $stored);

    $this->tester->execute([
        '--identifier' => 'example.com',
        '--storage'    => $this->dir,
    ]);

    expect($this->tester->getDisplay())->toContain('www.example.com');
});

it('exits with 1 when the certificate has expired, for monitoring', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(daysUntilExpiry: -1));

    $this->tester->execute(['--identifier' => 'example.com', '--storage' => $this->dir]);

    expect($this->tester->getStatusCode())->toBe(Command::FAILURE);
});

it('finds a certificate of any key type when --key-type is not given', function () {
    $this->storage->saveCertificate('example.com', makeStatusCert(keyType: KeyType::RSA_2048));

    $this->tester->execute(['--identifier' => 'Example.com', '--storage' => $this->dir]);

    expect($this->tester->getStatusCode())->toBe(Command::SUCCESS);
    expect($this->tester->getDisplay())->toContain('RSA 2048');
});
