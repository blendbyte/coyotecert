<?php

declare(strict_types=1);

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Storage\StorageAccountAdapter;

it('exists returns false when no account key is stored', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, 'letsencrypt');

    expect($adapter->exists())->toBeFalse();
});

it('savePrivateKey() stores the key so exists() and getPrivateKey() see it', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, 'letsencrypt');
    $pem     = rsaKeyPem();

    $adapter->savePrivateKey($pem, KeyType::RSA_2048);

    expect($adapter->exists())->toBeTrue();
    expect($adapter->getPrivateKey())->toBe($pem);
    expect($storage->getAccountKeyType('letsencrypt'))->toBe(KeyType::RSA_2048);
});

it('scopes the key to the provider slug', function () {
    $storage = new InMemoryStorage();
    (new StorageAccountAdapter($storage, 'letsencrypt'))->savePrivateKey(rsaKeyPem(), KeyType::RSA_2048);

    expect((new StorageAccountAdapter($storage, 'zerossl'))->exists())->toBeFalse();
});
