<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

/**
 * Base class for dns-01 challenge handlers.
 *
 * Extend this class, implement deploy() and cleanup(), and the handler will
 * automatically respond to the dns-01 challenge type. Deploy a TXT record at
 * _acme-challenge.{domain} with $keyAuthorization as the value; remove it in
 * cleanup().
 *
 * To avoid DNS propagation issues, call ->propagationDelay(30) (or however
 * many seconds your provider needs) before passing the handler to CoyoteCert.
 *
 * Example:
 *
 *   class MyDns01Handler extends AbstractDns01Handler
 *   {
 *       public function deploy(string $domain, string $token, string $keyAuth): void
 *       {
 *           MyDns::setTxt($this->challengeName($domain), $keyAuth);
 *       }
 *
 *       public function cleanup(string $domain, string $token): void
 *       {
 *           MyDns::deleteTxt($this->challengeName($domain));
 *       }
 *   }
 *
 *   $handler = new MyDns01Handler()->propagationDelay(30);
 */
abstract class AbstractDns01Handler implements ChallengeHandlerInterface
{
    private int $propagationDelaySecs = 0;

    final public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::DNS;
    }

    /**
     * Return a copy of this handler that sleeps for $seconds after deploy()
     * before returning, giving DNS time to propagate.
     */
    public function propagationDelay(int $seconds): static
    {
        $clone = clone $this;
        $clone->propagationDelaySecs = max(0, $seconds);

        return $clone;
    }

    /**
     * The TXT record name for the given domain.
     * Always '_acme-challenge.{domain}'.
     */
    protected function challengeName(string $domain): string
    {
        return '_acme-challenge.' . $domain;
    }

    /**
     * Sleep for the configured propagation delay, if any.
     * Call this at the end of deploy() implementations.
     */
    protected function sleepForPropagation(): void
    {
        if ($this->propagationDelaySecs > 0) {
            sleep($this->propagationDelaySecs);
        }
    }
}
