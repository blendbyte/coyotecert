<?php

namespace CoyoteCert\Exceptions;

class RateLimitException extends AcmeException
{
    public function __construct(string $message, private readonly ?int $retryAfter = null)
    {
        parent::__construct($message);
    }

    /**
     * Seconds the server asked us to wait, or null when the header was absent.
     */
    public function getRetryAfter(): ?int
    {
        return $this->retryAfter;
    }
}
