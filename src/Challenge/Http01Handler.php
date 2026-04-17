<?php

namespace CoyoteCert\Challenge;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

/**
 * Deploys HTTP-01 challenges by writing token files into a webroot directory.
 *
 * The file is placed at:
 *   {webroot}/.well-known/acme-challenge/{token}
 *
 * with the content:
 *   {token}.{accountThumbprint}
 *
 * Make sure your web server serves files from this path without authentication.
 */
class Http01Handler implements ChallengeHandlerInterface
{
    public function __construct(private readonly string $webroot) {}

    public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::HTTP;
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        if (!preg_match('/^[a-zA-Z0-9_\-]+$/', $token)) {
            throw new ChallengeException(
                sprintf('Invalid ACME token "%s": must match [a-zA-Z0-9_-]+.', $token),
            );
        }

        $dir = $this->challengeDir();

        if ($this->ancestorBlocksMkdir($dir)) {
            throw new ChallengeException(
                sprintf('Could not create challenge directory "%s".', $dir),
            );
        }

        if (!is_dir($dir) && !mkdir($dir, 0o755, true) && !is_dir($dir)) {
            throw new ChallengeException(
                sprintf('Could not create challenge directory "%s".', $dir),
            );
        }

        $path = $dir . $token;

        if (is_dir($path)) {
            throw new ChallengeException(
                sprintf('Could not write challenge file "%s": path is a directory.', $path),
            );
        }

        if (file_put_contents($path, $keyAuthorization) === false) {
            throw new ChallengeException(
                sprintf('Could not write challenge file "%s".', $path),
            );
        }
    }

    public function cleanup(string $domain, string $token): void
    {
        if (!preg_match('/^[a-zA-Z0-9_\-]+$/', $token)) {
            return;
        }

        $path = $this->challengeDir() . $token;

        if (file_exists($path)) {
            unlink($path);
        }
    }

    private function challengeDir(): string
    {
        return rtrim($this->webroot, '/') . '/.well-known/acme-challenge/';
    }

    private function ancestorBlocksMkdir(string $dir): bool
    {
        $path = rtrim($dir, '/\\');
        while ($path !== '' && $path !== dirname($path)) {
            if (file_exists($path)) {
                return !is_dir($path);
            }
            $path = dirname($path);
        }

        return false;
    }
}
