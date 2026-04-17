<?php

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;
use CoyoteCert\Support\LocalFileAccount;

beforeEach(function () {
    $this->dir     = sys_get_temp_dir() . '/coyote-lfa-' . uniqid();
    $this->account = new LocalFileAccount($this->dir);
});

afterEach(function () {
    if (is_dir($this->dir)) {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }
});

it('exists returns false when no keys are stored', function () {
    expect($this->account->exists())->toBeFalse();
});

it('generateNewKeys creates private and public key files', function () {
    expect($this->account->generateNewKeys())->toBeTrue();
    expect($this->account->exists())->toBeTrue();
});

it('generateNewKeys creates an EC key when KeyType::EC_P256 is passed', function () {
    expect($this->account->generateNewKeys(KeyType::EC_P256))->toBeTrue();
    expect($this->account->exists())->toBeTrue();
    expect($this->account->getPrivateKey())->toContain('PRIVATE KEY');
});

it('getPrivateKey returns a PEM string after key generation', function () {
    $this->account->generateNewKeys();
    expect($this->account->getPrivateKey())->toContain('PRIVATE KEY');
});

it('getPublicKey returns a PEM string after key generation', function () {
    $this->account->generateNewKeys();
    expect($this->account->getPublicKey())->toContain('PUBLIC KEY');
});

it('getPrivateKey throws when no key has been generated', function () {
    expect(fn() => $this->account->getPrivateKey())
        ->toThrow(StorageException::class);
});

it('getPublicKey throws when no key has been generated', function () {
    expect(fn() => $this->account->getPublicKey())
        ->toThrow(StorageException::class);
});

it('trailing slash is normalised in the path', function () {
    $account = new LocalFileAccount($this->dir . '/');
    $account->generateNewKeys();
    expect($account->exists())->toBeTrue();
});

it('exists returns false when the directory exists but key files are absent', function () {
    mkdir($this->dir, 0o755, true);
    expect($this->account->exists())->toBeFalse();
});

it('generateNewKeys throws when the directory cannot be created', function () {
    // Create a FILE at the path so mkdir inside it fails
    file_put_contents($this->dir, 'not-a-dir');

    expect(fn() => $this->account->generateNewKeys())
        ->toThrow(StorageException::class, 'was not created');

    @unlink($this->dir);
});

it('savePrivateKey() stores the key and getPrivateKey() returns the same PEM', function () {
    // Create directory and seed with a key so savePrivateKey() has a dir to write into
    $this->account->generateNewKeys();

    // Generate a fresh RSA key PEM to save
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $newPem,
    );

    $this->account->savePrivateKey($newPem, \CoyoteCert\Enums\KeyType::RSA_2048);

    expect($this->account->getPrivateKey())->toBe($newPem);
});

it('savePrivateKey() also derives and persists the public key', function () {
    $this->account->generateNewKeys();

    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $newPem,
    );

    $this->account->savePrivateKey($newPem, \CoyoteCert\Enums\KeyType::RSA_2048);

    expect($this->account->getPublicKey())->toContain('PUBLIC KEY');
});

it('generateNewKeys() throws StorageException when file write fails (read-only dir)', function () {
    // Create the directory first, then make it read-only so file_put_contents fails
    mkdir($this->dir, 0o555, true);

    // Skip this test when running as root (root can write to 0555 dirs)
    if (posix_geteuid() === 0) {
        chmod($this->dir, 0o755);
        $this->markTestSkipped('Running as root — chmod restriction does not apply.');
    }

    // Suppress the PHP E_WARNING emitted by file_put_contents on permission failure
    // so Pest does not show this test as WARN.
    set_error_handler(static fn() => true);
    try {
        expect(fn() => $this->account->generateNewKeys())
            ->toThrow(StorageException::class, 'Failed to write keys');
    } finally {
        restore_error_handler();
        chmod($this->dir, 0o755);
    }
});

it('savePrivateKey() throws CryptoException when the PEM is not a valid private key', function () {
    $this->account->generateNewKeys(); // ensure directory exists

    expect(fn() => $this->account->savePrivateKey('not-a-pem', KeyType::RSA_2048))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Cannot load private key');
});

it('getKey() throws StorageException when file exists but cannot be read (mode 0000)', function () {
    $this->account->generateNewKeys();

    // Locate the private key file and make it unreadable
    $files = glob($this->dir . '/*private*');
    expect($files)->not->toBeEmpty();

    $keyFile = $files[0];
    chmod($keyFile, 0o000);

    // Skip when running as root
    if (posix_geteuid() === 0) {
        chmod($keyFile, 0o644);
        $this->markTestSkipped('Running as root — chmod restriction does not apply.');
    }

    // Suppress the PHP E_WARNING from file_get_contents on permission failure.
    set_error_handler(static fn() => true);
    try {
        expect(fn() => $this->account->getPrivateKey())
            ->toThrow(StorageException::class);
    } finally {
        restore_error_handler();
        chmod($keyFile, 0o644);
    }
});
