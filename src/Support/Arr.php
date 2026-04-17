<?php

namespace CoyoteCert\Support;

use ArrayAccess;

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
            return value($default);
        }

        if (is_null($key)) {
            return $array;
        }

        if (static::exists($array, $key)) {
            return $array[$key];
        }

        // Dot-notation traversal is used by the test suite and kept for backward
        // compatibility (e.g. 'a.b.c' descends into nested arrays).
        if (!is_string($key) || strpos($key, '.') === false) {
            return $array[$key] ?? value($default);
        }

        foreach (explode('.', $key) as $segment) {
            if (static::accessible($array) && static::exists($array, $segment)) {
                $array = $array[$segment];
            } else {
                return value($default);
            }
        }

        return $array;
    }

    /**
     * @param array<mixed> $array
     * @param mixed $default
     * @return mixed
     */
    public static function first(array $array, ?callable $callback = null, mixed $default = null): mixed
    {
        if (is_null($callback)) {
            if (empty($array)) {
                return value($default);
            }

            foreach ($array as $item) {
                return $item;
            }
        }

        foreach ($array as $key => $value) {
            if ($callback($value, $key)) {
                return $value;
            }
        }

        return value($default);
    }
}
