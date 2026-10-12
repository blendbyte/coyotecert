<?php

declare(strict_types=1);

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;
use CoyoteCert\Storage\DatabaseStorage;
use CoyoteCert\Storage\StoredCertificate;

function makeSqliteStorage(string $table = 'coyote_cert_storage'): DatabaseStorage
{
    $pdo = new PDO('sqlite::memory:', options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec(<<<SQL
        CREATE TABLE IF NOT EXISTS `{$table}` (
            `store_key` VARCHAR(255) NOT NULL,
            `value`     TEXT        NOT NULL,
            PRIMARY KEY (`store_key`)
        )
        SQL);

    return new DatabaseStorage($pdo, $table);
}

function makeDatabaseCert(KeyType $keyType = KeyType::EC_P256): StoredCertificate
{
    return new StoredCertificate(
        certificate: '-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----',
        privateKey: '-----BEGIN EC PRIVATE KEY-----\nMIIBtest\n-----END EC PRIVATE KEY-----',
        fullchain: 'fullchain-db',
        caBundle: 'cabundle-db',
        issuedAt: new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt: new DateTimeImmutable('2026-06-01T00:00:00+00:00'),
        domains: ['db.example.com'],
        keyType: $keyType,
    );
}

it('has no account key initially', function () {
    $storage = makeSqliteStorage();
    expect($storage->hasAccountKey('letsencrypt'))->toBeFalse();
});

it('saves and retrieves an account key', function () {
    $storage = makeSqliteStorage();
    $storage->saveAccountKey('letsencrypt', 'pem-data', KeyType::RSA_2048);

    expect($storage->hasAccountKey('letsencrypt'))->toBeTrue();
    expect($storage->getAccountKey('letsencrypt'))->toBe('pem-data');
    expect($storage->getAccountKeyType('letsencrypt'))->toBe(KeyType::RSA_2048);
});

it('overwrites an existing account key', function () {
    $storage = makeSqliteStorage();
    $storage->saveAccountKey('letsencrypt', 'old-pem', KeyType::RSA_2048);
    $storage->saveAccountKey('letsencrypt', 'new-pem', KeyType::EC_P256);

    expect($storage->getAccountKey('letsencrypt'))->toBe('new-pem');
    expect($storage->getAccountKeyType('letsencrypt'))->toBe(KeyType::EC_P256);
});

it('isolates account keys by provider slug', function () {
    $storage = makeSqliteStorage();
    $storage->saveAccountKey('letsencrypt', 'le-pem', KeyType::EC_P256);
    $storage->saveAccountKey('zerossl', 'zs-pem', KeyType::RSA_2048);

    expect($storage->getAccountKey('letsencrypt'))->toBe('le-pem');
    expect($storage->getAccountKey('zerossl'))->toBe('zs-pem');
});

it('throws when getAccountKey is called with no key stored', function () {
    $storage = makeSqliteStorage();
    expect(fn() => $storage->getAccountKey('letsencrypt'))->toThrow(StorageException::class);
});

it('throws when getAccountKeyType is called with no key type stored', function () {
    $storage = makeSqliteStorage();
    expect(fn() => $storage->getAccountKeyType('letsencrypt'))->toThrow(StorageException::class);
});

it('has no certificate initially', function () {
    $storage = makeSqliteStorage();
    expect($storage->hasCertificate('example.com', KeyType::EC_P256))->toBeFalse();
    expect($storage->getCertificate('example.com', KeyType::EC_P256))->toBeNull();
});

it('saves and retrieves a certificate', function () {
    $storage = makeSqliteStorage();
    $cert    = makeDatabaseCert();
    $storage->saveCertificate('db.example.com', $cert);

    expect($storage->hasCertificate('db.example.com', KeyType::EC_P256))->toBeTrue();

    $loaded = $storage->getCertificate('db.example.com', KeyType::EC_P256);
    expect($loaded->toArray())->toBe($cert->toArray());
});

it('overwrites an existing certificate', function () {
    $storage = makeSqliteStorage();
    $storage->saveCertificate('example.com', makeDatabaseCert());

    $updated = new StoredCertificate(
        certificate: 'new-cert',
        privateKey: 'new-key',
        fullchain: 'new-full',
        caBundle: 'new-ca',
        issuedAt: new DateTimeImmutable('2026-03-01T00:00:00+00:00'),
        expiresAt: new DateTimeImmutable('2026-09-01T00:00:00+00:00'),
        domains: ['example.com'],
        keyType: KeyType::EC_P256,
    );
    $storage->saveCertificate('example.com', $updated);

    expect($storage->getCertificate('example.com', KeyType::EC_P256)->certificate)->toBe('new-cert');
});

it('stores RSA and ECDSA certificates under separate keys', function () {
    $storage = makeSqliteStorage();
    $rsa     = makeDatabaseCert(KeyType::RSA_2048);
    $ec      = makeDatabaseCert(KeyType::EC_P256);

    $storage->saveCertificate('example.com', $rsa);
    $storage->saveCertificate('example.com', $ec);

    expect($storage->getCertificate('example.com', KeyType::RSA_2048)->keyType)->toBe(KeyType::RSA_2048);
    expect($storage->getCertificate('example.com', KeyType::EC_P256)->keyType)->toBe(KeyType::EC_P256);
});

it('createTableSql returns a non-empty SQL string', function () {
    $sql = DatabaseStorage::createTableSql();
    expect($sql)->toBeString()->not->toBeEmpty();
    expect($sql)->toContain('coyote_cert_storage');
});

it('createTableSql uses the provided table name', function () {
    $sql = DatabaseStorage::createTableSql('my_table');
    expect($sql)->toContain('my_table');
});

it('constructor throws InvalidArgumentException for a table name with invalid characters', function () {
    $pdo = new PDO('sqlite::memory:');

    expect(fn() => new DatabaseStorage($pdo, 'invalid-name!'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

it('set() uses ON CONFLICT syntax for pgsql driver', function () {
    $mockPdo = new class extends \PDO {
        public array $capturedSql = [];
        public function __construct() {}
        public function getAttribute(int $attribute): mixed
        {
            return 'pgsql';
        }
        public function prepare(string $query, array $options = []): \PDOStatement|false
        {
            $this->capturedSql[] = $query;

            return new class extends \PDOStatement {
                public function execute(?array $params = null): bool
                {
                    return true;
                }
            };
        }
    };

    $storage = new DatabaseStorage($mockPdo);
    $storage->saveAccountKey('letsencrypt', 'pem-data', KeyType::RSA_2048);

    $pgsqlSqls = array_filter(
        $mockPdo->capturedSql,
        fn($sql) => str_contains($sql, 'ON CONFLICT'),
    );
    expect($pgsqlSqls)->not->toBeEmpty();
});

it('set() uses ON DUPLICATE KEY UPDATE syntax for non-sqlite/non-pgsql drivers', function () {
    $mockPdo = new class extends \PDO {
        public array $capturedSql = [];

        public function __construct() {}

        public function getAttribute(int $attribute): mixed
        {
            return 'mysql';
        }

        public function prepare(string $query, array $options = []): \PDOStatement|false
        {
            $this->capturedSql[] = $query;

            return new class extends \PDOStatement {
                public function execute(?array $params = null): bool
                {
                    return true;
                }
            };
        }
    };

    $storage = new DatabaseStorage($mockPdo);
    $storage->saveAccountKey('letsencrypt', 'pem-data', KeyType::RSA_2048);

    $mysqlSqls = array_filter(
        $mockPdo->capturedSql,
        fn($sql) => str_contains($sql, 'ON DUPLICATE KEY UPDATE'),
    );
    expect($mysqlSqls)->not->toBeEmpty();
});

// ── SEC-08: createTableSql() identifier validation ────────────────────────────

it('createTableSql() returns SQL for a valid table name', function () {
    $sql = DatabaseStorage::createTableSql('my_certs');
    expect($sql)->toContain('my_certs');
});

it('createTableSql() throws InvalidArgumentException for a table name with a space', function () {
    expect(fn() => DatabaseStorage::createTableSql('bad table'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

it('createTableSql() throws InvalidArgumentException for a table name with a backtick', function () {
    expect(fn() => DatabaseStorage::createTableSql('`evil`'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

it('createTableSql() throws InvalidArgumentException for a table name with a semicolon', function () {
    expect(fn() => DatabaseStorage::createTableSql('certs; DROP TABLE users; --'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

// ── Driver portability ────────────────────────────────────────────────────────

it('works end to end on SQLite with the table from createTableSql()', function () {
    $pdo = new PDO('sqlite::memory:', options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec(DatabaseStorage::createTableSql(driver: 'sqlite'));
    $storage = new DatabaseStorage($pdo);

    $storage->saveCertificate('db.example.com', makeDatabaseCert());
    $storage->saveCertificate('db.example.com', makeDatabaseCert()); // upsert path
    $storage->saveAccountKey('letsencrypt', 'pem', KeyType::EC_P256);

    expect($storage->getCertificate('db.example.com', KeyType::EC_P256)?->domains)->toBe(['db.example.com']);
    expect($storage->getAccountKey('letsencrypt'))->toBe('pem');

    $storage->deleteCertificate('db.example.com', KeyType::EC_P256);
    expect($storage->hasCertificate('db.example.com', KeyType::EC_P256))->toBeFalse();
});

it('quotes identifiers with double quotes on PostgreSQL, never backticks', function () {
    $mockPdo = new class extends \PDO {
        public array $capturedSql = [];

        public function __construct() {}

        public function getAttribute(int $attribute): mixed
        {
            return 'pgsql';
        }

        public function prepare(string $query, array $options = []): \PDOStatement|false
        {
            $this->capturedSql[] = $query;

            return new class extends \PDOStatement {
                public function execute(?array $params = null): bool
                {
                    return true;
                }

                public function fetchColumn(int $column = 0): mixed
                {
                    return false;
                }
            };
        }
    };

    $storage = new DatabaseStorage($mockPdo);
    $storage->hasCertificate('example.com', KeyType::EC_P256);
    $storage->saveAccountKey('letsencrypt', 'pem', KeyType::EC_P256);
    $storage->deleteCertificate('example.com', KeyType::EC_P256);

    expect(implode("\n", $mockPdo->capturedSql))->not->toContain('`')->toContain('"coyote_cert_storage"');
    expect(DatabaseStorage::createTableSql(driver: 'pgsql'))->not->toContain('`');
});

it('createTableSql() rejects an unsupported driver', function () {
    expect(fn() => DatabaseStorage::createTableSql(driver: 'sqlsrv'))
        ->toThrow(\InvalidArgumentException::class, 'Unsupported PDO driver "sqlsrv"');
});

it('rejects PDO drivers it cannot generate SQL for', function () {
    $pdo = new class extends \PDO {
        public function __construct() {}

        public function getAttribute(int $attribute): mixed
        {
            return 'sqlsrv';
        }
    };

    expect(fn() => new DatabaseStorage($pdo))->toThrow(\InvalidArgumentException::class, 'Unsupported PDO driver "sqlsrv"');
});

it('reports database errors as StorageException', function () {
    $pdo     = new PDO('sqlite::memory:', options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $storage = new DatabaseStorage($pdo, 'missing_table');

    expect(fn() => $storage->hasAccountKey('letsencrypt'))
        ->toThrow(StorageException::class, 'Database storage query failed');
});

it('reports database errors as StorageException when PDO errors are silent', function () {
    $pdo     = new PDO('sqlite::memory:', options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT]);
    $storage = new DatabaseStorage($pdo, 'missing_table');

    expect(fn() => $storage->hasAccountKey('letsencrypt'))
        ->toThrow(StorageException::class, 'no such table');
});
