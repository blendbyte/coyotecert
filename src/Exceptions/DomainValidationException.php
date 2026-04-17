<?php

namespace CoyoteCert\Exceptions;

class DomainValidationException extends AcmeException
{
    public static function localHttpChallengeTestFailed(string $domain, string $code): self
    {
        return new self(sprintf(
            'The local HTTP challenge test for %s received an invalid response with a %s status code.',
            $domain,
            $code,
        ));
    }

    public static function localDnsChallengeTestFailed(string $domain): self
    {
        return new self(sprintf(
            "Couldn't fetch the correct DNS records for %s.",
            $domain,
        ));
    }
}
