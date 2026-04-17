<?php

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Storage\StoredCertificate;

function makeStoredCert(): StoredCertificate
{
    return new StoredCertificate(
        certificate: '-----BEGIN CERTIFICATE-----',
        privateKey: '-----BEGIN PRIVATE KEY-----',
        fullchain: 'fullchain',
        caBundle: 'ca',
        issuedAt: new DateTimeImmutable(),
        expiresAt: new DateTimeImmutable('+90 days'),
        domains: ['example.com'],
    );
}

it('has no account key initially', function () {
    expect((new InMemoryStorage())->hasAccountKey())->toBeFalse();
});

it('saves and retrieves an account key', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey('pem-data', KeyType::RSA_2048);

    expect($storage->hasAccountKey())->toBeTrue();
    expect($storage->getAccountKey())->toBe('pem-data');
    expect($storage->getAccountKeyType())->toBe(KeyType::RSA_2048);
});

it('throws when getting account key before saving', function () {
    expect(fn() => (new InMemoryStorage())->getAccountKey())
        ->toThrow(\CoyoteCert\Exceptions\StorageException::class);
});

it('throws when getting account key type before saving', function () {
    expect(fn() => (new InMemoryStorage())->getAccountKeyType())
        ->toThrow(\CoyoteCert\Exceptions\StorageException::class);
});

it('has no certificate initially', function () {
    expect((new InMemoryStorage())->hasCertificate('example.com'))->toBeFalse();
    expect((new InMemoryStorage())->getCertificate('example.com'))->toBeNull();
});

it('saves and retrieves a certificate', function () {
    $storage = new InMemoryStorage();
    $cert    = makeStoredCert();
    $storage->saveCertificate('example.com', $cert);

    expect($storage->hasCertificate('example.com'))->toBeTrue();
    expect($storage->getCertificate('example.com'))->toBe($cert);
});

it('isolates certificates by domain', function () {
    $storage = new InMemoryStorage();
    $cert    = makeStoredCert();
    $storage->saveCertificate('example.com', $cert);

    expect($storage->hasCertificate('other.com'))->toBeFalse();
    expect($storage->getCertificate('other.com'))->toBeNull();
});

it('deleteCertificate() removes the certificate', function () {
    $storage = new InMemoryStorage();
    $storage->saveCertificate('example.com', makeStoredCert());
    $storage->deleteCertificate('example.com');

    expect($storage->hasCertificate('example.com'))->toBeFalse();
    expect($storage->getCertificate('example.com'))->toBeNull();
});

it('deleteCertificate() is a no-op for unknown domain', function () {
    $storage = new InMemoryStorage();
    $storage->deleteCertificate('unknown.com'); // must not throw
    expect(true)->toBeTrue();
});

it('overwrites an existing certificate', function () {
    $storage = new InMemoryStorage();
    $first   = makeStoredCert();
    $storage->saveCertificate('example.com', $first);

    $second = new StoredCertificate(
        certificate: 'new-cert',
        privateKey: 'new-key',
        fullchain: 'new-fullchain',
        caBundle: 'new-ca',
        issuedAt: new DateTimeImmutable(),
        expiresAt: new DateTimeImmutable('+90 days'),
        domains: ['example.com'],
    );
    $storage->saveCertificate('example.com', $second);

    expect($storage->getCertificate('example.com'))->toBe($second);
});
