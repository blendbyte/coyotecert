<?php

declare(strict_types=1);

namespace CoyoteCert\Enums;

enum AuthorizationChallengeEnum: string
{
    case HTTP     = 'http-01';
    case DNS      = 'dns-01';
    case TLS_ALPN = 'tls-alpn-01';
}
