<?php

declare(strict_types=1);

namespace CoyoteCert\Support;

use ArrayAccess;
use Closure;

class Arr
{
    /**
     * @param mixed $value
     */
    public static function accessible(mixed $value): bool
    {
        return is_array($value) || $value instanceof ArrayAccess;
    }

    /**
     * @param array<mixed>|ArrayAccess<mixed, mixed> $array
     * @param int|string $key
     */
    public static function exists(array|ArrayAccess $array, int|string $key): bool
    {
        if ($array instanceof ArrayAccess) {
            return $array->offsetExists($key);
        }

        return array_key_exists($key, $array);
    }

    /**
     * @param mixed $array
     * @param int|string|null $key
     * @param mixed $default
     * @return mixed
     */
    public static function get(mixed $array, int|string|null $key, mixed $default = null): mixed
    {
        if (!static::accessible($array)) {
            return $default instanceof Closure ? $default() : $default;
        }

        if (is_null($key)) {
            return $array;
        }

        if (static::exists($array, $key)) {
            return $array[$key];
        }

        return $default instanceof Closure ? $default() : $default;
    }
}
