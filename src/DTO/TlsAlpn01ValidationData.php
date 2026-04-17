<?php

namespace CoyoteCert\DTO;

readonly class TlsAlpn01ValidationData
{
    public function __construct(
        public string $identifier,
        public string $token,
        public string $keyAuthorization,
    ) {}
}
