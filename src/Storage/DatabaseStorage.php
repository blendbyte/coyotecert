<?php

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;

/**
 * PDO-backed storage.
 *
 * Creates a single key-value table. Run {@see DatabaseStorage::createTable()}
 * once during your application's setup or migration step.
 */
class DatabaseStorage implements StorageInterface
{
    private const KEY_ACCOUNT_PEM  = '__account_pem';
    private const KEY_ACCOUNT_TYPE = '__account_key_type';

    public function __construct(
        private readonly \PDO   $pdo,
        private readonly string $table = 'coyote_cert_storage',
    ) {
        $this->validateIdentifier($this->table);
    }

    /**
     * Ensures an identifier (table/column name) contains only safe characters.
     * Rejects anything that is not [a-zA-Z0-9_].
     */
    private function validateIdentifier(string $name): void
    {
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
            throw new \InvalidArgumentException(
                sprintf('Invalid SQL identifier "%s": only [a-zA-Z0-9_] are allowed.', $name)
            );
        }
    }

    /**
     * Returns the SQL statement that creates the storage table.
     * Execute this once during your application's setup / migration.
     *
     * Supports MySQL/MariaDB, PostgreSQL, and SQLite.
     */
    public static function createTableSql(string $table = 'coyote_cert_storage'): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS `{$table}` (
                `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `store_key`  VARCHAR(255)  NOT NULL,
                `value`      MEDIUMTEXT    NOT NULL,
                `updated_at` TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                UNIQUE KEY `uq_store_key` (`store_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            SQL;
    }

    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(): bool
    {
        return $this->get(self::KEY_ACCOUNT_PEM) !== null;
    }

    public function getAccountKey(): string
    {
        $value = $this->get(self::KEY_ACCOUNT_PEM);

        if ($value === null) {
            throw new StorageException('No account key found in database storage.');
        }

        return $value;
    }

    public function getAccountKeyType(): KeyType
    {
        $value = $this->get(self::KEY_ACCOUNT_TYPE);

        if ($value === null) {
            throw new StorageException('No account key type found in database storage.');
        }

        return KeyType::from($value);
    }

    public function saveAccountKey(string $pem, KeyType $type): void
    {
        $this->set(self::KEY_ACCOUNT_PEM, $pem);
        $this->set(self::KEY_ACCOUNT_TYPE, $type->value);
    }

    // ── Certificates ─────────────────────────────────────────────────────────

    public function hasCertificate(string $domain): bool
    {
        return $this->get($this->certKey($domain)) !== null;
    }

    public function getCertificate(string $domain): ?StoredCertificate
    {
        $json = $this->get($this->certKey($domain));

        if ($json === null) {
            return null;
        }

        return StoredCertificate::fromArray(
            json_decode($json, true, 512, JSON_THROW_ON_ERROR)
        );
    }

    public function saveCertificate(string $domain, StoredCertificate $cert): void
    {
        $this->set(
            $this->certKey($domain),
            json_encode($cert->toArray(), JSON_THROW_ON_ERROR)
        );
    }

    // ── PDO helpers ───────────────────────────────────────────────────────────

    private function certKey(string $domain): string
    {
        return 'cert:' . $domain;
    }

    private function get(string $key): ?string
    {
        $stmt = $this->pdo->prepare(
            "SELECT `value` FROM `{$this->table}` WHERE `store_key` = :key LIMIT 1"
        );
        $stmt->execute([':key' => $key]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        return $row !== false ? (string) $row['value'] : null;
    }

    private function set(string $key, string $value): void
    {
        $driver = $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);

        if ($driver === 'sqlite') {
            $sql = "INSERT OR REPLACE INTO `{$this->table}` (`store_key`, `value`) VALUES (:key, :value)";
        } elseif ($driver === 'pgsql') {
            $sql = "INSERT INTO \"{$this->table}\" (\"store_key\", \"value\")
                    VALUES (:key, :value)
                    ON CONFLICT (\"store_key\") DO UPDATE SET \"value\" = EXCLUDED.\"value\"";
        } else {
            $sql = "INSERT INTO `{$this->table}` (`store_key`, `value`)
                    VALUES (:key, :value)
                    ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)";
        }

        $this->pdo->prepare($sql)->execute([':key' => $key, ':value' => $value]);
    }
}
