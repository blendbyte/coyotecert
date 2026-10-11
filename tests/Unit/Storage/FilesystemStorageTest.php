<?php

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;

beforeEach(function () {
    $this->dir     = sys_get_temp_dir() . '/coyote-cert-test-' . uniqid();
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

function makeFileCert(KeyType $keyType = KeyType::EC_P256): StoredCertificate
{
    return new StoredCertificate(
        certificate: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
        privateKey: '-----BEGIN EC PRIVATE KEY-----\nMIIB\n-----END EC PRIVATE KEY-----',
        fullchain: 'fullchain-data',
        caBundle: 'ca-bundle-data',
        issuedAt: new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt: new DateTimeImmutable('2026-04-01T00:00:00+00:00'),
        domains: ['example.com'],
        keyType: $keyType,
    );
}

it('has no account key initially', function () {
    expect($this->storage->hasAccountKey('letsencrypt'))->toBeFalse();
});

it('saves and loads an account key', function () {
    $this->storage->saveAccountKey('letsencrypt', 'my-pem-data', KeyType::EC_P256);

    expect($this->storage->hasAccountKey('letsencrypt'))->toBeTrue();
    expect($this->storage->getAccountKey('letsencrypt'))->toBe('my-pem-data');
    expect($this->storage->getAccountKeyType('letsencrypt'))->toBe(KeyType::EC_P256);
});

it('isolates account keys by provider slug', function () {
    $this->storage->saveAccountKey('letsencrypt', 'le-pem', KeyType::EC_P256);
    $this->storage->saveAccountKey('zerossl', 'zs-pem', KeyType::RSA_2048);

    expect($this->storage->getAccountKey('letsencrypt'))->toBe('le-pem');
    expect($this->storage->getAccountKey('zerossl'))->toBe('zs-pem');
    expect(file_exists($this->dir . '/account-letsencrypt.pem'))->toBeTrue();
    expect(file_exists($this->dir . '/account-zerossl.pem'))->toBeTrue();
});

it('creates the storage directory on first write', function () {
    expect(is_dir($this->dir))->toBeFalse();
    $this->storage->saveAccountKey('letsencrypt', 'pem', KeyType::RSA_2048);
    expect(is_dir($this->dir))->toBeTrue();
});

it('has no certificate initially', function () {
    expect($this->storage->hasCertificate('example.com', KeyType::EC_P256))->toBeFalse();
    expect($this->storage->getCertificate('example.com', KeyType::EC_P256))->toBeNull();
});

it('saves and loads a certificate', function () {
    $cert = makeFileCert();
    $this->storage->saveCertificate('example.com', $cert);

    expect($this->storage->hasCertificate('example.com', KeyType::EC_P256))->toBeTrue();

    $loaded = $this->storage->getCertificate('example.com', KeyType::EC_P256);
    expect($loaded->toArray())->toBe($cert->toArray());
});

it('sanitises the domain for use as a filename', function () {
    $cert = makeFileCert();
    $this->storage->saveCertificate('*.example.com', $cert);

    expect($this->storage->hasCertificate('*.example.com', KeyType::EC_P256))->toBeTrue();
    expect($this->storage->getCertificate('*.example.com', KeyType::EC_P256)->domains)->toBe(['example.com']);
});

it('overwrites an existing certificate file', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());

    $updated = new StoredCertificate(
        certificate: 'new-cert',
        privateKey: 'new-key',
        fullchain: 'new-fullchain',
        caBundle: 'new-ca',
        issuedAt: new DateTimeImmutable('2026-06-01T00:00:00+00:00'),
        expiresAt: new DateTimeImmutable('2026-09-01T00:00:00+00:00'),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    );
    $this->storage->saveCertificate('example.com', $updated);

    expect($this->storage->getCertificate('example.com', KeyType::EC_P256)->certificate)->toBe('new-cert');
});

it('stores RSA and ECDSA certificates in separate files', function () {
    $rsa = makeFileCert(KeyType::RSA_2048);
    $ec  = makeFileCert(KeyType::EC_P256);

    $this->storage->saveCertificate('example.com', $rsa);
    $this->storage->saveCertificate('example.com', $ec);

    expect($this->storage->getCertificate('example.com', KeyType::RSA_2048)->keyType)->toBe(KeyType::RSA_2048);
    expect($this->storage->getCertificate('example.com', KeyType::EC_P256)->keyType)->toBe(KeyType::EC_P256);
    expect(glob($this->dir . '/example.com.*.cert.json'))->toHaveCount(2);
});

it('getAccountKey throws when account key file does not exist', function () {
    expect(fn() => $this->storage->getAccountKey('letsencrypt'))
        ->toThrow(\CoyoteCert\Exceptions\StorageException::class, 'does not exist');
});

it('saveAccountKey throws when the storage directory cannot be created', function () {
    // Create a FILE at the directory path so mkdir inside ensureDirectory() fails
    file_put_contents($this->dir, 'not-a-dir');

    expect(fn() => $this->storage->saveAccountKey('letsencrypt', 'pem', KeyType::RSA_2048))
        ->toThrow(\CoyoteCert\Exceptions\StorageException::class, 'could not be created');

    @unlink($this->dir);
});

it('deleteCertificate() removes the stored file', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());
    $this->storage->deleteCertificate('example.com', KeyType::EC_P256);

    expect($this->storage->hasCertificate('example.com', KeyType::EC_P256))->toBeFalse();
});

it('deleteCertificate() is a no-op for unknown domain', function () {
    expect(fn() => $this->storage->deleteCertificate('unknown.com', KeyType::EC_P256))->not->toThrow(\Throwable::class);
});

// ── PEM file output ───────────────────────────────────────────────────────────

it('saveCertificate writes PEM files alongside the JSON', function () {
    $cert = makeFileCert();
    $this->storage->saveCertificate('example.com', $cert);

    $base = $this->dir . '/example.com.EC_P256.';
    expect(file_get_contents($base . 'certificate.pem'))->toBe($cert->certificate);
    expect(file_get_contents($base . 'private_key.pem'))->toBe($cert->privateKey);
    expect(file_get_contents($base . 'fullchain.pem'))->toBe($cert->fullchain);
    expect(file_get_contents($base . 'ca.pem'))->toBe($cert->caBundle);
});

it('private_key.pem is mode 0600 and public PEM files are mode 0644', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());

    $base = $this->dir . '/example.com.EC_P256.';
    expect(decoct(fileperms($base . 'private_key.pem') & 0o777))->toBe('600');
    expect(decoct(fileperms($base . 'certificate.pem') & 0o777))->toBe('644');
    expect(decoct(fileperms($base . 'fullchain.pem') & 0o777))->toBe('644');
    expect(decoct(fileperms($base . 'ca.pem') & 0o777))->toBe('644');
})->skip(fn() => function_exists('posix_getuid') && posix_getuid() === 0, 'root bypasses chmod checks');

it('cert.json and account files are mode 0600 even when the file already exists with looser permissions', function () {
    $base = $this->dir . '/example.com.EC_P256.';
    mkdir($this->dir, 0o755, true);
    touch($base . 'cert.json');
    chmod($base . 'cert.json', 0o644);

    $this->storage->saveCertificate('example.com', makeFileCert());
    // A slug ending in "ca" must not be mistaken for the public ca.pem
    $this->storage->saveAccountKey('myca', 'account-key', KeyType::EC_P256);

    expect(decoct(fileperms($base . 'cert.json') & 0o777))->toBe('600');
    expect(decoct(fileperms($this->dir . '/account-myca.pem') & 0o777))->toBe('600');
    expect(decoct(fileperms($this->dir . '/account-myca.json') & 0o777))->toBe('600');
})->skip(fn() => function_exists('posix_getuid') && posix_getuid() === 0, 'root bypasses chmod checks');

it('saveCertificate overwrites PEM files on renewal', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());

    $renewed = new StoredCertificate(
        certificate: 'renewed-cert',
        privateKey: 'renewed-key',
        fullchain: 'renewed-fullchain',
        caBundle: 'renewed-ca',
        issuedAt: new DateTimeImmutable('2026-06-01T00:00:00+00:00'),
        expiresAt: new DateTimeImmutable('2026-09-01T00:00:00+00:00'),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    );
    $this->storage->saveCertificate('example.com', $renewed);

    $base = $this->dir . '/example.com.EC_P256.';
    expect(file_get_contents($base . 'certificate.pem'))->toBe('renewed-cert');
    expect(file_get_contents($base . 'private_key.pem'))->toBe('renewed-key');
    expect(file_get_contents($base . 'fullchain.pem'))->toBe('renewed-fullchain');
    expect(file_get_contents($base . 'ca.pem'))->toBe('renewed-ca');
});

it('deleteCertificate removes PEM files', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());
    $this->storage->deleteCertificate('example.com', KeyType::EC_P256);

    $base = $this->dir . '/example.com.EC_P256.';
    expect(file_exists($base . 'certificate.pem'))->toBeFalse();
    expect(file_exists($base . 'private_key.pem'))->toBeFalse();
    expect(file_exists($base . 'fullchain.pem'))->toBeFalse();
    expect(file_exists($base . 'ca.pem'))->toBeFalse();
});

it('RSA and ECDSA certificates write separate PEM file sets', function () {
    $this->storage->saveCertificate('example.com', makeFileCert(KeyType::RSA_2048));
    $this->storage->saveCertificate('example.com', makeFileCert(KeyType::EC_P256));

    expect(file_exists($this->dir . '/example.com.RSA_2048.fullchain.pem'))->toBeTrue();
    expect(file_exists($this->dir . '/example.com.EC_P256.fullchain.pem'))->toBeTrue();
});

// ── StoredCertificate helpers ─────────────────────────────────────────────────

it('isExpired() returns false for a future certificate', function () {
    $cert = new StoredCertificate(
        certificate: '',
        privateKey: '',
        fullchain: '',
        caBundle: '',
        issuedAt: new DateTimeImmutable('-1 day'),
        expiresAt: new DateTimeImmutable('+90 days'),
        domains: ['example.com'],
    );
    expect($cert->isExpired())->toBeFalse();
});

it('isExpired() returns true for a past certificate', function () {
    $cert = new StoredCertificate(
        certificate: '',
        privateKey: '',
        fullchain: '',
        caBundle: '',
        issuedAt: new DateTimeImmutable('-100 days'),
        expiresAt: new DateTimeImmutable('-1 day'),
        domains: ['example.com'],
    );
    expect($cert->isExpired())->toBeTrue();
});

it('expiresWithin() returns true when expiry is within the window', function () {
    $cert = new StoredCertificate(
        certificate: '',
        privateKey: '',
        fullchain: '',
        caBundle: '',
        issuedAt: new DateTimeImmutable('-60 days'),
        expiresAt: new DateTimeImmutable('+10 days'),
        domains: ['example.com'],
    );
    expect($cert->expiresWithin(30))->toBeTrue();
});

it('expiresWithin() returns false when expiry is beyond the window', function () {
    $cert = new StoredCertificate(
        certificate: '',
        privateKey: '',
        fullchain: '',
        caBundle: '',
        issuedAt: new DateTimeImmutable('-1 day'),
        expiresAt: new DateTimeImmutable('+60 days'),
        domains: ['example.com'],
    );
    expect($cert->expiresWithin(30))->toBeFalse();
});

it('writeFile throws StorageException when the file cannot be written', function () {
    // Create the directory first so ensureDirectory() passes, then remove write permission.
    mkdir($this->dir, 0o755, true);
    chmod($this->dir, 0o555); // read+execute only

    try {
        expect(fn() => $this->storage->saveAccountKey('letsencrypt', 'pem', KeyType::EC_P256))
            ->toThrow(\CoyoteCert\Exceptions\StorageException::class, 'Could not write');
    } finally {
        chmod($this->dir, 0o755); // restore so afterEach cleanup can remove the dir
    }
})->skip(fn() => function_exists('posix_getuid') && posix_getuid() === 0, 'root can write to any directory');

it('replaces files atomically via rename and leaves no temp files behind', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());
    $path  = $this->dir . '/example.com.EC_P256.private_key.pem';
    $inode = fileinode($path);

    $this->storage->saveCertificate('example.com', makeFileCert());
    clearstatcache();

    // A rename swaps in a new inode; an in-place write would keep the old one
    expect(fileinode($path))->not->toBe($inode);
    expect(glob($this->dir . '/.coyote-*') ?: [])->toBe([]);
});
