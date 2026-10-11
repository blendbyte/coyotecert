<?php

use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\RevocationReason;
use CoyoteCert\Storage\InMemoryStorage;
use Tests\Integration\Helpers\NoOpHttp01Handler;

it('revokes a previously issued certificate', function () {
    $storage = new InMemoryStorage();

    $cert = CoyoteCert::with(pebble())
        ->storage($storage)
        ->identifiers('revoke.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    CoyoteCert::with(pebble())
        ->storage($storage)
        ->revoke($cert);

    // The CA now knows the certificate as revoked, so revoking it again is rejected
    expect(fn() => CoyoteCert::with(pebble())->storage($storage)->revoke($cert))
        ->toThrow(\CoyoteCert\Exceptions\AcmeException::class);
})->skip(fn() => !pebbleAvailable(), 'Pebble not running, skipping integration tests');

it('revokes with a specific reason code', function () {
    $storage = new InMemoryStorage();

    $cert = CoyoteCert::with(pebble())
        ->storage($storage)
        ->identifiers('revoke-reason.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    CoyoteCert::with(pebble())
        ->storage($storage)
        ->revoke($cert, RevocationReason::KeyCompromise);

    try {
        CoyoteCert::with(pebble())->storage($storage)->revoke($cert);
        $this->fail('Revoking twice should be rejected');
    } catch (\CoyoteCert\Exceptions\AcmeException $e) {
        expect($e->getProblemType())->toBe('urn:ietf:params:acme:error:alreadyRevoked');
    }
})->skip(fn() => !pebbleAvailable(), 'Pebble not running, skipping integration tests');

it('throws when revoke is called without storage', function () {
    $storage = new InMemoryStorage();

    $cert = CoyoteCert::with(pebble())
        ->storage($storage)
        ->identifiers('revoke-nostorage.example.com')
        ->challenge(new NoOpHttp01Handler())
        ->skipLocalTest()
        ->issue();

    expect(fn() => CoyoteCert::with(pebble())->revoke($cert))
        ->toThrow(\CoyoteCert\Exceptions\AcmeException::class);
})->skip(fn() => !pebbleAvailable(), 'Pebble not running — skipping integration tests');
