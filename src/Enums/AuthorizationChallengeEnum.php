<?php

namespace CoyoteCert\Enums;

enum AuthorizationChallengeEnum: string
{
    case HTTP        = 'http-01';
    case DNS         = 'dns-01';
    case DNS_PERSIST = 'dns-persist-01';
}
