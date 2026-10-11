<?php

declare(strict_types=1);

namespace CoyoteCert\Support;

class Url
{
    public static function extractId(string $url): string
    {
        if (empty($url)) {
            return '';
        }

        $url = rtrim($url, '/');

        $positionLastSlash = strrpos($url, '/');

        return substr($url, ($positionLastSlash + 1));
    }
}
