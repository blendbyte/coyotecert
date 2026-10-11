<?php

declare(strict_types=1);

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\AcmeException;

/**
 * Typed reads from decoded JSON (CA and DNS provider responses, stored certificates),
 * so malformed data fails with a clear message instead of a TypeError deep in the library.
 */
final class Arr
{
    /**
     * A required string.
     *
     * @param array<mixed> $data
     * @throws AcmeException when the key is missing or not a string
     */
    public static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (!is_string($value)) {
            throw new AcmeException(sprintf('Unexpected data: "%s" is missing or not a string.', $key));
        }

        return $value;
    }

    /**
     * An optional string: null when missing or not a string.
     *
     * @param array<mixed> $data
     */
    public static function stringOrNull(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * An identifier that APIs send as a string or an integer, as a string; null otherwise.
     *
     * @param array<mixed> $data
     */
    public static function id(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return is_string($value) || is_int($value) ? (string) $value : null;
    }

    /**
     * An optional object/array: empty when missing or not an array.
     *
     * @param array<mixed> $data
     * @return array<mixed>
     */
    public static function array(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        return is_array($value) ? $value : [];
    }

    /**
     * The string entries of an optional list.
     *
     * @param array<mixed> $data
     * @return list<string>
     */
    public static function strings(array $data, string $key): array
    {
        return array_values(array_filter(self::array($data, $key), is_string(...)));
    }

    /**
     * The array entries of an optional list (e.g. challenges, identifiers).
     *
     * @param array<mixed> $data
     * @return list<array<mixed>>
     */
    public static function arrays(array $data, string $key): array
    {
        return array_values(array_filter(self::array($data, $key), is_array(...)));
    }
}
