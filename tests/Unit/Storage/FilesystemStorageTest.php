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

function makeFileCert(): StoredCertificate
{
    return new StoredCertificate(
        certificate: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
        privateKey:  '-----BEGIN EC PRIVATE KEY-----\nMIIB\n-----END EC PRIVATE KEY-----',
        fullchain:   'fullchain-data',
        caBundle:    'ca-bundle-data',
        issuedAt:    new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt:   new DateTimeImmutable('2026-04-01T00:00:00+00:00'),
        domains:     ['example.com'],
    );
}

it('has no account key initially', function () {
    expect($this->storage->hasAccountKey())->toBeFalse();
});

it('saves and loads an account key', function () {
    $this->storage->saveAccountKey('my-pem-data', KeyType::EC_P256);

    expect($this->storage->hasAccountKey())->toBeTrue();
    expect($this->storage->getAccountKey())->toBe('my-pem-data');
    expect($this->storage->getAccountKeyType())->toBe(KeyType::EC_P256);
});

it('creates the storage directory on first write', function () {
    expect(is_dir($this->dir))->toBeFalse();
    $this->storage->saveAccountKey('pem', KeyType::RSA_2048);
    expect(is_dir($this->dir))->toBeTrue();
});

it('has no certificate initially', function () {
    expect($this->storage->hasCertificate('example.com'))->toBeFalse();
    expect($this->storage->getCertificate('example.com'))->toBeNull();
});

it('saves and loads a certificate', function () {
    $cert = makeFileCert();
    $this->storage->saveCertificate('example.com', $cert);

    expect($this->storage->hasCertificate('example.com'))->toBeTrue();

    $loaded = $this->storage->getCertificate('example.com');
    expect($loaded->toArray())->toBe($cert->toArray());
});

it('sanitises the domain for use as a filename', function () {
    $cert = makeFileCert();
    $this->storage->saveCertificate('*.example.com', $cert);

    expect($this->storage->hasCertificate('*.example.com'))->toBeTrue();
    expect($this->storage->getCertificate('*.example.com')->domains)->toBe(['example.com']);
});

it('overwrites an existing certificate file', function () {
    $this->storage->saveCertificate('example.com', makeFileCert());

    $updated = new StoredCertificate(
        certificate: 'new-cert',
        privateKey:  'new-key',
        fullchain:   'new-fullchain',
        caBundle:    'new-ca',
        issuedAt:    new DateTimeImmutable('2026-06-01T00:00:00+00:00'),
        expiresAt:   new DateTimeImmutable('2026-09-01T00:00:00+00:00'),
        domains:     ['example.com'],
    );
    $this->storage->saveCertificate('example.com', $updated);

    expect($this->storage->getCertificate('example.com')->certificate)->toBe('new-cert');
});

it('getAccountKey throws when account key file does not exist', function () {
    // readFile() throws when the file path does not exist — verifies the
    // "Storage file ... does not exist" error path inside readFile().
    expect(fn () => $this->storage->getAccountKey())
        ->toThrow(\CoyoteCert\Exceptions\LetsEncryptClientException::class, 'does not exist');
});

it('saveAccountKey throws when the storage directory cannot be created', function () {
    // Create a FILE at the directory path so mkdir inside ensureDirectory() fails
    file_put_contents($this->dir, 'not-a-dir');

    expect(fn () => $this->storage->saveAccountKey('pem', KeyType::RSA_2048))
        ->toThrow(\CoyoteCert\Exceptions\LetsEncryptClientException::class, 'could not be created');

    @unlink($this->dir);
});
