<?php

declare(strict_types=1);

namespace CoyoteCert\Exceptions;

use RuntimeException;

class AcmeException extends RuntimeException
{
    /** @var list<array<mixed>> */
    private readonly array $subproblems;

    /**
     * @param list<array<mixed>> $subproblems RFC 8555 §6.7 per-identifier problems.
     * @param string|null $problemType The ACME problem type, e.g. urn:ietf:params:acme:error:rateLimited.
     */
    public function __construct(
        string $message = '',
        array $subproblems = [],
        int $code = 0,
        ?\Throwable $previous = null,
        private readonly ?string $problemType = null,
    ) {
        $this->subproblems = $subproblems;
        parent::__construct($message, $code, $previous);
    }

    /** The ACME problem type (RFC 8555 §6.7) when the CA returned one, e.g. "urn:ietf:params:acme:error:caa". */
    public function getProblemType(): ?string
    {
        return $this->problemType;
    }

    /** @return list<array<mixed>> */
    public function getSubproblems(): array
    {
        return $this->subproblems;
    }
}
