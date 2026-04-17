<?php

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

function makeDatabaseCert(): StoredCertificate
{
    return new StoredCertificate(
        certificate: '-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----',
        privateKey:  '-----BEGIN EC PRIVATE KEY-----\nMIIBtest\n-----END EC PRIVATE KEY-----',
        fullchain:   'fullchain-db',
        caBundle:    'cabundle-db',
        issuedAt:    new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt:   new DateTimeImmutable('2026-06-01T00:00:00+00:00'),
        domains:     ['db.example.com'],
    );
}

it('has no account key initially', function () {
    $storage = makeSqliteStorage();
    expect($storage->hasAccountKey())->toBeFalse();
});

it('saves and retrieves an account key', function () {
    $storage = makeSqliteStorage();
    $storage->saveAccountKey('pem-data', KeyType::RSA_2048);

    expect($storage->hasAccountKey())->toBeTrue();
    expect($storage->getAccountKey())->toBe('pem-data');
    expect($storage->getAccountKeyType())->toBe(KeyType::RSA_2048);
});

it('overwrites an existing account key', function () {
    $storage = makeSqliteStorage();
    $storage->saveAccountKey('old-pem', KeyType::RSA_2048);
    $storage->saveAccountKey('new-pem', KeyType::EC_P256);

    expect($storage->getAccountKey())->toBe('new-pem');
    expect($storage->getAccountKeyType())->toBe(KeyType::EC_P256);
});

it('throws when getAccountKey is called with no key stored', function () {
    $storage = makeSqliteStorage();
    expect(fn () => $storage->getAccountKey())->toThrow(StorageException::class);
});

it('throws when getAccountKeyType is called with no key type stored', function () {
    $storage = makeSqliteStorage();
    expect(fn () => $storage->getAccountKeyType())->toThrow(StorageException::class);
});

it('has no certificate initially', function () {
    $storage = makeSqliteStorage();
    expect($storage->hasCertificate('example.com'))->toBeFalse();
    expect($storage->getCertificate('example.com'))->toBeNull();
});

it('saves and retrieves a certificate', function () {
    $storage = makeSqliteStorage();
    $cert    = makeDatabaseCert();
    $storage->saveCertificate('db.example.com', $cert);

    expect($storage->hasCertificate('db.example.com'))->toBeTrue();

    $loaded = $storage->getCertificate('db.example.com');
    expect($loaded->toArray())->toBe($cert->toArray());
});

it('overwrites an existing certificate', function () {
    $storage = makeSqliteStorage();
    $storage->saveCertificate('example.com', makeDatabaseCert());

    $updated = new StoredCertificate(
        certificate: 'new-cert',
        privateKey:  'new-key',
        fullchain:   'new-full',
        caBundle:    'new-ca',
        issuedAt:    new DateTimeImmutable('2026-03-01T00:00:00+00:00'),
        expiresAt:   new DateTimeImmutable('2026-09-01T00:00:00+00:00'),
        domains:     ['example.com'],
    );
    $storage->saveCertificate('example.com', $updated);

    expect($storage->getCertificate('example.com')->certificate)->toBe('new-cert');
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

    expect(fn () => new DatabaseStorage($pdo, 'invalid-name!'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

it('set() uses ON CONFLICT syntax for pgsql driver', function () {
    $mockPdo = new class extends \PDO {
        public array $capturedSql = [];
        public function __construct() {}
        public function getAttribute(int $attribute): mixed { return 'pgsql'; }
        public function prepare(string $query, array $options = []): \PDOStatement|false {
            $this->capturedSql[] = $query;
            return new class extends \PDOStatement {
                public function execute(?array $params = null): bool { return true; }
            };
        }
    };

    $storage = new DatabaseStorage($mockPdo);
    $storage->saveAccountKey('pem-data', KeyType::RSA_2048);

    $pgsqlSqls = array_filter(
        $mockPdo->capturedSql,
        fn ($sql) => str_contains($sql, 'ON CONFLICT')
    );
    expect($pgsqlSqls)->not->toBeEmpty();
});

it('set() uses ON DUPLICATE KEY UPDATE syntax for non-sqlite/non-pgsql drivers', function () {
    // Mock PDO that reports 'mysql' as driver but records prepared SQL
    $mockPdo = new class extends \PDO {
        public array $capturedSql = [];

        public function __construct() {} // intentionally skip parent — this is a mock

        public function getAttribute(int $attribute): mixed
        {
            return 'mysql'; // simulate MySQL driver
        }

        public function prepare(string $query, array $options = []): \PDOStatement|false
        {
            $this->capturedSql[] = $query;
            return new class extends \PDOStatement {
                public function execute(?array $params = null): bool { return true; }
            };
        }
    };

    $storage = new DatabaseStorage($mockPdo);
    $storage->saveAccountKey('pem-data', KeyType::RSA_2048);

    $mysqlSqls = array_filter(
        $mockPdo->capturedSql,
        fn ($sql) => str_contains($sql, 'ON DUPLICATE KEY UPDATE')
    );
    expect($mysqlSqls)->not->toBeEmpty();
});

// ── SEC-08: createTableSql() identifier validation ────────────────────────────

it('createTableSql() returns SQL for a valid table name', function () {
    $sql = DatabaseStorage::createTableSql('my_certs');
    expect($sql)->toContain('my_certs');
});

it('createTableSql() throws InvalidArgumentException for a table name with a space', function () {
    expect(fn () => DatabaseStorage::createTableSql('bad table'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

it('createTableSql() throws InvalidArgumentException for a table name with a backtick', function () {
    expect(fn () => DatabaseStorage::createTableSql('`evil`'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

it('createTableSql() throws InvalidArgumentException for a table name with a semicolon', function () {
    expect(fn () => DatabaseStorage::createTableSql('certs; DROP TABLE users; --'))
        ->toThrow(\InvalidArgumentException::class, 'Invalid SQL identifier');
});

