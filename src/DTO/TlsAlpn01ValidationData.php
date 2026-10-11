<?php

declare(strict_types=1);

namespace CoyoteCert\DTO;

readonly class TlsAlpn01ValidationData
{
    public function __construct(
        public string $identifier,
        public string $token,
        public string $keyAuthorization,
    ) {}
}
