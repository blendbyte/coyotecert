<?php

namespace CoyoteCert\DTO;

readonly class EabCredentials
{
    public function __construct(
        public string $kid,
        public string $hmacKey,
    ) {}
}
