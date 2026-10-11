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

    /**
     * @param array<string> $found
     */
    public static function localDnsChallengeTestFailed(
        string $domain,
        string $record = '',
        string $nameserver = '',
        string $expected = '',
        array $found = [],
        ?string $lookupError = null,
    ): self {
        $base = sprintf("Couldn't fetch the correct DNS records for %s.", $domain);

        if ($record === '') {
            return new self($base);
        }

        if ($lookupError !== null) {
            return new self(sprintf('%s DNS lookup failed: %s', $base, $lookupError));
        }

        $foundStr = empty($found)
            ? '(none)'
            : implode(', ', array_map(fn($v) => '"' . $v . '"', $found));

        return new self(sprintf(
            '%s Queried %s TXT at %s — expected: "%s" — found: %s',
            $base,
            $record,
            $nameserver,
            $expected,
            $foundStr,
        ));
    }

    /**
     * @param array<int, array<string, mixed>> $errors
     */
    public static function challengeInvalid(string $domain, array $errors): self
    {
        $details = array_map(
            static fn(array $e) => sprintf(
                '%s: %s',
                $e['domainValidationType'] ?? '?',
                $e['error']['detail']      ?? $e['error']['type'] ?? 'no detail provided',
            ),
            $errors,
        );

        // Expose the challenge errors in the RFC 8555 §6.7 subproblem shape
        $identifier  = ['type' => filter_var($domain, FILTER_VALIDATE_IP) ? 'ip' : 'dns', 'value' => $domain];
        $subproblems = array_map(static fn(array $e): array => (array) $e['error'] + ['identifier' => $identifier], $errors);

        return new self(sprintf(
            'The CA marked the authorization for %s as invalid.%s',
            $domain,
            empty($details) ? '' : ' ' . implode(' ', $details),
        ), $subproblems);
    }
}
