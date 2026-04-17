<?php

namespace CoyoteCert\Exceptions;

use RuntimeException;

class AcmeException extends RuntimeException
{
    /** @var array<int, array<string, mixed>> */
    private readonly array $subproblems;

    /**
     * @param array<int, array<string, mixed>> $subproblems RFC 8555 §6.7 per-identifier problems.
     */
    public function __construct(string $message = '', array $subproblems = [], int $code = 0, ?\Throwable $previous = null)
    {
        $this->subproblems = $subproblems;
        parent::__construct($message, $code, $previous);
    }

    /** @return array<int, array<string, mixed>> */
    public function getSubproblems(): array
    {
        return $this->subproblems;
    }
}
