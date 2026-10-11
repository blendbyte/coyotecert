<?php

declare(strict_types=1);

namespace CoyoteCert\Storage;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\StorageException;

class DatabaseStorage implements StorageInterface
{
    public function __construct(
        private readonly \PDO   $pdo,
        private readonly string $table = 'coyote_cert_storage',
    ) {
        self::validateIdentifier($this->table);
    }

    /**
     * Returns the SQL statement that creates the storage table for $driver, the PDO driver
     * name ('mysql' for MySQL/MariaDB, 'pgsql', or 'sqlite'). Execute it once during your
     * application's setup / migration:
     *
     *   $pdo->exec(DatabaseStorage::createTableSql(driver: $pdo->getAttribute(PDO::ATTR_DRIVER_NAME)));
     */
    public static function createTableSql(string $table = 'coyote_cert_storage', string $driver = 'mysql'): string
    {
        self::validateIdentifier($table);

        return match ($driver) {
            'mysql' => <<<SQL
                CREATE TABLE IF NOT EXISTS `{$table}` (
                    `store_key`  VARCHAR(255) NOT NULL,
                    `value`      MEDIUMTEXT   NOT NULL,
                    `updated_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (`store_key`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                SQL,
            'pgsql', 'sqlite' => <<<SQL
                CREATE TABLE IF NOT EXISTS "{$table}" (
                    "store_key" VARCHAR(255) NOT NULL PRIMARY KEY,
                    "value"     TEXT         NOT NULL
                )
                SQL,
            default => throw new \InvalidArgumentException(
                sprintf('Unsupported PDO driver "%s": use mysql, pgsql or sqlite.', $driver),
            ),
        };
    }

    // ── Account key ──────────────────────────────────────────────────────────

    public function hasAccountKey(string $providerSlug): bool
    {
        return $this->get('account:' . $providerSlug . ':pem') !== null;
    }

    public function getAccountKey(string $providerSlug): string
    {
        return $this->get('account:' . $providerSlug . ':pem')
            ?? throw new StorageException('No account key found in database storage.');
    }

    public function getAccountKeyType(string $providerSlug): KeyType
    {
        $value = $this->get('account:' . $providerSlug . ':key_type')
            ?? throw new StorageException('No account key type found in database storage.');

        return KeyType::from($value);
    }

    public function saveAccountKey(string $providerSlug, string $pem, KeyType $type): void
    {
        $this->set('account:' . $providerSlug . ':pem', $pem);
        $this->set('account:' . $providerSlug . ':key_type', $type->value);
    }

    // ── Certificates ─────────────────────────────────────────────────────────

    public function hasCertificate(string $domain, KeyType $keyType): bool
    {
        return $this->get($this->certKey($domain, $keyType)) !== null;
    }

    public function getCertificate(string $domain, KeyType $keyType): ?StoredCertificate
    {
        $json = $this->get($this->certKey($domain, $keyType));

        return $json !== null ? StoredCertificate::fromJson($json) : null;
    }

    public function saveCertificate(string $domain, StoredCertificate $cert): void
    {
        $this->set(
            $this->certKey($domain, $cert->keyType),
            json_encode($cert->toArray(), JSON_THROW_ON_ERROR),
        );
    }

    public function deleteCertificate(string $domain, KeyType $keyType): void
    {
        $this->pdo
            ->prepare(sprintf('DELETE FROM %s WHERE %s = :key', $this->quote($this->table), $this->quote('store_key')))
            ->execute([':key' => $this->certKey($domain, $keyType)]);
    }

    // ── PDO helpers ───────────────────────────────────────────────────────────

    private function certKey(string $domain, KeyType $keyType): string
    {
        return 'cert:' . $domain . ':' . $keyType->value;
    }

    private function get(string $key): ?string
    {
        $stmt = $this->pdo->prepare(sprintf(
            'SELECT %s FROM %s WHERE %s = :key LIMIT 1',
            $this->quote('value'),
            $this->quote($this->table),
            $this->quote('store_key'),
        ));
        $stmt->execute([':key' => $key]);
        $value = $stmt->fetchColumn();

        return is_string($value) ? $value : null;
    }

    private function set(string $key, string $value): void
    {
        [$table, $keyColumn, $valueColumn] = [$this->quote($this->table), $this->quote('store_key'), $this->quote('value')];

        if ($this->isMysql()) {
            // A second placeholder instead of VALUES(), which MySQL 8 deprecates (MariaDB lacks the alias syntax)
            $this->pdo->prepare(sprintf(
                'INSERT INTO %s (%s, %s) VALUES (:key, :value) ON DUPLICATE KEY UPDATE %s = :update_value',
                $table,
                $keyColumn,
                $valueColumn,
                $valueColumn,
            ))->execute([':key' => $key, ':value' => $value, ':update_value' => $value]);

            return;
        }

        $this->pdo->prepare(sprintf(
            'INSERT INTO %s (%s, %s) VALUES (:key, :value) ON CONFLICT (%s) DO UPDATE SET %s = excluded.%s',
            $table,
            $keyColumn,
            $valueColumn,
            $keyColumn,
            $valueColumn,
            $valueColumn,
        ))->execute([':key' => $key, ':value' => $value]);
    }

    /** MySQL quotes identifiers with backticks; PostgreSQL and SQLite with standard double quotes. */
    private function quote(string $identifier): string
    {
        return $this->isMysql() ? "`{$identifier}`" : "\"{$identifier}\"";
    }

    private function isMysql(): bool
    {
        return !in_array($this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME), ['pgsql', 'sqlite'], true);
    }

    private static function validateIdentifier(string $name): void
    {
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
            throw new \InvalidArgumentException(
                sprintf('Invalid SQL identifier "%s": only [a-zA-Z0-9_] are allowed.', $name),
            );
        }
    }
}
