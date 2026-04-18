<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\DomainValidationException;
use CoyoteCert\Interfaces\HttpClientInterface;
use RuntimeException;
use Spatie\Dns\Dns;

class LocalChallengeTest
{
    private const DEFAULT_NAMESERVER = 'dns.google.com';

    public static function http(
        string $domain,
        string $token,
        string $keyAuthorization,
        HttpClientInterface $httpClient,
    ): void {
        $response = $httpClient->get('http://' . $domain . '/.well-known/acme-challenge/' . $token, maxRedirects: 1);

        if (trim($response->rawBody()) === $keyAuthorization) {
            return;
        }

        throw DomainValidationException::localHttpChallengeTestFailed(
            $domain,
            (string) $response->getHttpResponseCode(),
        );
    }

    public static function dns(string $domain, string $name, string $value): void
    {
        $challenge   = sprintf('%s.%s', $name, $domain);
        $nameserver  = self::DEFAULT_NAMESERVER;
        $foundTxt    = [];
        $lookupError = null;

        try {
            $nameserver = self::getNameserver($domain);

            // Try to validate TXT records directly.
            $txtRecords = self::getRecords($nameserver, $challenge, DNS_TXT);
            $foundTxt   = array_map(fn($r) => $r->txt(), $txtRecords);

            if (self::validateTxtRecords($txtRecords, $value)) {
                return;
            }

            // Try to validate a CNAME record pointing to a TXT record containing the correct value.
            $cnameRecords = self::getRecords($nameserver, $challenge, DNS_CNAME);
            if (self::validateCnameRecords($cnameRecords, $value)) {
                return;
            }
        } catch (RuntimeException $e) {
            $lookupError = $e->getMessage();
        }

        throw DomainValidationException::localDnsChallengeTestFailed(
            $domain,
            $challenge,
            $nameserver,
            $value,
            $foundTxt,
            $lookupError,
        );
    }

    /** @param array<mixed> $records */
    private static function validateTxtRecords(array $records, string $value): bool
    {
        foreach ($records as $record) {
            if ($record->txt() === $value) {
                return true;
            }
        }

        return false;
    }

    /** @param array<mixed> $records */
    private static function validateCnameRecords(array $records, string $value, int $depth = 0): bool
    {
        if ($depth >= 10) {
            return false;
        }

        foreach ($records as $record) {
            $nameserver = self::getNameserver($record->target());
            $txtRecords = self::getRecords($nameserver, $record->target(), DNS_TXT);
            if (self::validateTxtRecords($txtRecords, $value)) {
                return true;
            }

            // If this is another CNAME, follow it.
            $cnameRecords = self::getRecords($nameserver, $record->target(), DNS_CNAME);
            if (!empty($cnameRecords)) {
                if (self::validateCnameRecords($cnameRecords, $value, $depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static function getNameserver(string $domain): string
    {
        $dnsResolver = new Dns();
        $parts       = explode('.', $domain);

        // Walk up the zone hierarchy until we find NS records.
        // e.g. certtest.oa1.net has no NS → try oa1.net → found.
        for ($i = 0; $i < count($parts) - 1; $i++) {
            $candidate = implode('.', array_slice($parts, $i));
            try {
                $result = $dnsResolver->getRecords($candidate, DNS_NS);
                if (!empty($result)) {
                    return $result[0]->target();
                }
            } catch (\Throwable) {
                // No NS at this level; try parent zone.
            }
        }

        return self::DEFAULT_NAMESERVER;
    }

    /**
     * Look up _acme-challenge TXT records from the authoritative NS.
     *
     * @return array{0: string, 1: string, 2: string[]} [nameserver, ip, found_values]
     */
    public static function lookupTxt(string $domain): array
    {
        try {
            $ns      = self::getNameserver($domain);
            $ip      = gethostbyname($ns);
            $records = self::getRecords($ns, '_acme-challenge.' . $domain, DNS_TXT);
            $found   = array_map(fn($r) => $r->txt(), $records);

            return [$ns, $ip !== $ns ? $ip : 'unresolved', $found];
        } catch (\Throwable) {
            return [self::DEFAULT_NAMESERVER, 'unresolved', []];
        }
    }

    /** @return array<mixed> */
    private static function getRecords(string $nameserver, string $name, int $dnsType): array
    {
        $dnsResolver = new Dns();

        return $dnsResolver
            ->useNameserver($nameserver)
            ->getRecords($name, $dnsType);
    }
}
