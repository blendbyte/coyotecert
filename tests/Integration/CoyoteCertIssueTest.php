<?php

use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Storage\StoredCertificate;
use Tests\Integration\Helpers\NoOpHttp01Handler;

it('issues a certificate with default key types (RSA account, EC_P256 cert)', function () {
    $cert = CoyoteCert::with(pebble())
        ->storage(new InMemoryStorage())
        ->domains('test.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    expect($cert)->toBeInstanceOf(StoredCertificate::class);
    expect($cert->certificate)->toContain('-----BEGIN CERTIFICATE-----');
    expect($cert->privateKey)->toContain('-----BEGIN');
    expect($cert->fullchain)->toContain('-----BEGIN CERTIFICATE-----');
    expect($cert->domains)->toBe(['test.example.com']);
    expect(openssl_x509_parse($cert->certificate))->toBeArray();
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');

it('issues a certificate with an EC P-256 account key', function () {
    $cert = CoyoteCert::with(pebble())
        ->storage(new InMemoryStorage())
        ->domains('ec-account.example.com')
        ->accountKeyType(KeyType::EC_P256)
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    expect($cert->certificate)->toContain('-----BEGIN CERTIFICATE-----');
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');

it('reuses an existing account on a second issue', function () {
    $storage = new InMemoryStorage();

    $first = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('reuse.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    // Second call reuses the account key already in $storage
    $second = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('reuse.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    expect($first->certificate)->not->toBe($second->certificate);
    expect($second->certificate)->toContain('-----BEGIN CERTIFICATE-----');
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');

it('issueOrRenew returns the cached cert when still valid', function () {
    $storage = new InMemoryStorage();

    $issued = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('cached.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    $returned = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('cached.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issueOrRenew(daysBeforeExpiry: 1);

    expect($returned->certificate)->toBe($issued->certificate);
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');

it('issues a certificate with the shortlived profile', function () {
    $cert = CoyoteCert::with(pebble())
        ->storage(new InMemoryStorage())
        ->domains('profile.example.com')
        ->profile('shortlived')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    expect($cert->certificate)->toContain('-----BEGIN CERTIFICATE-----');
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');
