<?php

use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\RevocationReason;
use CoyoteCert\Storage\InMemoryStorage;
use Tests\Integration\Helpers\NoOpHttp01Handler;

it('revokes a previously issued certificate', function () {
    $storage = new InMemoryStorage();

    $cert = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('revoke.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    $result = CoyoteCert::with(pebble())
        ->storage($storage)
        ->revoke($cert);

    expect($result)->toBeTrue();
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');

it('revokes with a specific reason code', function () {
    $storage = new InMemoryStorage();

    $cert = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('revoke-reason.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    $result = CoyoteCert::with(pebble())
        ->storage($storage)
        ->revoke($cert, RevocationReason::KeyCompromise);

    expect($result)->toBeTrue();
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');

it('throws when revoke is called without storage', function () {
    $storage = new InMemoryStorage();

    $cert = CoyoteCert::with(pebble())
        ->storage($storage)
        ->domains('revoke-nostorage.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    expect(fn() => CoyoteCert::with(pebble())->revoke($cert))
        ->toThrow(\CoyoteCert\Exceptions\AcmeException::class);
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');
