<?php

declare(strict_types=1);

namespace CoyoteCert\DTO;

readonly class Http01ValidationData
{
    public function __construct(
        public string $identifier,
        public string $filename,
        public string $content,
        public string $keyAuthorization,
    ) {}
}
