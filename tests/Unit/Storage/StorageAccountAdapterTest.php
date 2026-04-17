<?php

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Storage\StorageAccountAdapter;

it('exists returns false when no account key is stored', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage);

    expect($adapter->exists())->toBeFalse();
});

it('generateNewKeys stores a key in storage', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, KeyType::RSA_2048);

    $result = $adapter->generateNewKeys();

    expect($result)->toBeTrue();
    expect($storage->hasAccountKey())->toBeTrue();
    expect($storage->getAccountKeyType())->toBe(KeyType::RSA_2048);
});

it('exists returns true after generateNewKeys', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, KeyType::RSA_2048);
    $adapter->generateNewKeys();

    expect($adapter->exists())->toBeTrue();
});

it('getPrivateKey returns the stored PEM', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, KeyType::RSA_2048);
    $adapter->generateNewKeys();

    $pem = $adapter->getPrivateKey();
    expect($pem)->toBeString()->toContain('PRIVATE KEY');
});

it('getPublicKey returns a public key PEM', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, KeyType::RSA_2048);
    $adapter->generateNewKeys();

    $pub = $adapter->getPublicKey();
    expect($pub)->toBeString()->toContain('PUBLIC KEY');
});

it('getPublicKey() throws CryptoException when the stored key PEM is not a valid private key', function () {
    $storage = new InMemoryStorage();
    // Store an invalid PEM so openssl_pkey_get_private() returns false (line 36)
    $storage->saveAccountKey('this-is-not-a-valid-pem', KeyType::RSA_2048);
    $adapter = new StorageAccountAdapter($storage);

    expect(fn() => $adapter->getPublicKey())
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Cannot load private key.');
});

it('savePrivateKey() delegates to storage->saveAccountKey()', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage);

    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem,
    );

    $adapter->savePrivateKey($pem, KeyType::RSA_2048);

    expect($storage->hasAccountKey())->toBeTrue();
    expect($storage->getAccountKey())->toBe($pem);
    expect($storage->getAccountKeyType())->toBe(KeyType::RSA_2048);
});

it('generateNewKeys() uses the keyTypeOverride when provided', function () {
    $storage = new InMemoryStorage();
    $adapter = new StorageAccountAdapter($storage, KeyType::RSA_2048);

    // Override with EC_P256 — the stored key should be EC, not RSA
    $result = $adapter->generateNewKeys(KeyType::EC_P256);

    expect($result)->toBeTrue();
    expect($storage->getAccountKeyType())->toBe(KeyType::EC_P256);
});
