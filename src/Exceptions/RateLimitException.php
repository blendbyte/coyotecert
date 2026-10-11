<?php

declare(strict_types=1);

namespace CoyoteCert\Exceptions;

class RateLimitException extends AcmeException
{
    /** @param array<int, array<string, mixed>> $subproblems */
    public function __construct(
        string $message,
        private readonly ?int $retryAfter = null,
        array $subproblems = [],
        ?string $problemType = null,
    ) {
        parent::__construct($message, $subproblems, problemType: $problemType);
    }

    /**
     * Seconds the server asked us to wait, or null when the header was absent.
     */
    public function getRetryAfter(): ?int
    {
        return $this->retryAfter;
    }
}
