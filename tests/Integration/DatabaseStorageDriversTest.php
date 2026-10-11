<?php

declare(strict_types=1);

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\DatabaseStorage;
use CoyoteCert\Storage\StoredCertificate;

/**
 * Runs DatabaseStorage against real servers when CI provides them through
 * COYOTE_TEST_PGSQL_DSN / COYOTE_TEST_MYSQL_DSN (user and password in COYOTE_TEST_DB_USER
 * and COYOTE_TEST_DB_PASSWORD). SQLite is covered by the unit tests.
 */
it('round-trips certificates and account keys', function (string $env) {
    if (!getenv($env)) {
        $this->markTestSkipped("{$env} not set");
    }

    $pdo = new PDO((string) getenv($env), getenv('COYOTE_TEST_DB_USER') ?: null, getenv('COYOTE_TEST_DB_PASSWORD') ?: null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

    // "order" is a reserved word, so this only works if every query quotes the table name
    $pdo->exec($driver === 'pgsql' ? 'DROP TABLE IF EXISTS "order"' : 'DROP TABLE IF EXISTS `order`');
    $pdo->exec(DatabaseStorage::createTableSql('order', $driver));

    $storage = new DatabaseStorage($pdo, 'order');
    $cert    = new StoredCertificate(
        certificate: 'cert',
        privateKey: 'key',
        fullchain: 'fullchain',
        caBundle: 'ca',
        issuedAt: new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt: new DateTimeImmutable('2026-04-01T00:00:00+00:00'),
        domains: ['db.example.com'],
        keyType: KeyType::EC_P256,
    );

    $storage->saveCertificate('db.example.com', $cert);
    $storage->saveCertificate('db.example.com', $cert); // upsert
    $storage->saveAccountKey('letsencrypt', 'first', KeyType::EC_P256);
    $storage->saveAccountKey('letsencrypt', 'second', KeyType::RSA_2048);

    expect($storage->getCertificate('db.example.com', KeyType::EC_P256)?->domains)->toBe(['db.example.com']);
    expect($storage->getAccountKey('letsencrypt'))->toBe('second');
    expect($storage->getAccountKeyType('letsencrypt'))->toBe(KeyType::RSA_2048);

    $storage->deleteCertificate('db.example.com', KeyType::EC_P256);
    expect($storage->hasCertificate('db.example.com', KeyType::EC_P256))->toBeFalse();
})->with([
    'PostgreSQL'    => ['COYOTE_TEST_PGSQL_DSN'],
    'MySQL/MariaDB' => ['COYOTE_TEST_MYSQL_DSN'],
]);
