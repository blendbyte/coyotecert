<?php

namespace CoyoteCert\Exceptions;

/**
 * Thrown when a DNS provider API returns an HTTP 4xx or 5xx response.
 *
 * Extends ChallengeException so existing catch (ChallengeException) handlers
 * are unaffected. When only a specific status code (e.g. 404) should be
 * swallowed, catch HttpChallengeException and check $httpStatus.
 */
class HttpChallengeException extends ChallengeException
{
    public function __construct(string $message, public readonly int $httpStatus)
    {
        parent::__construct($message);
    }
}
