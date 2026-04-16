<?php

namespace Tests\Integration\Helpers;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

/**
 * Challenge handler used in integration tests.
 * Does nothing — Pebble runs with PEBBLE_VA_ALWAYS_VALID=1 so no real file is needed.
 */
class NoOpHttp01Handler implements ChallengeHandlerInterface
{
    public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::HTTP;
    }

    public function deploy(string $domain, string $token, string $keyAuth): void {}

    public function cleanup(string $domain, string $token): void {}
}
