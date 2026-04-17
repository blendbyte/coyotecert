<?php

namespace CoyoteCert\DTO;

readonly class Dns01ValidationData
{
    public function __construct(
        public string $identifier,
        public string $name,
        public string $value,
        public string $keyAuthorization,
    ) {}
}
