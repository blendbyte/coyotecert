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
        // IPv6 identifiers (RFC 8738) need brackets in a URL; follow redirects like the CA does (RFC 8555 §8.3)
        $host     = filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $domain . ']' : $domain;
        $response = $httpClient->get('http://' . $host . '/.well-known/acme-challenge/' . $token, maxRedirects: 10);

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
        $nameservers = self::getNameservers($domain);

        // All authoritative nameservers must have the record — ACME validators check each one.
        foreach ($nameservers as $nameserver) {
            $foundTxt    = [];
            $lookupError = null;

            try {
                $txtRecords = self::getRecords($nameserver, $challenge, DNS_TXT);
                $foundTxt   = array_map(fn($r) => $r->txt(), $txtRecords);

                if (self::validateTxtRecords($txtRecords, $value)) {
                    continue;
                }

                if (self::validateTxtRecords(self::followCname($nameserver, $challenge), $value)) {
                    continue;
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

    /**
     * TXT records at the end of a CNAME chain starting at $name, each hop queried on the
     * target's own authoritative nameserver. CAs follow a CNAME-delegated _acme-challenge
     * (RFC 8555 §8.4), so the check has to as well.
     *
     * @return array<mixed>
     */
    private static function followCname(string $nameserver, string $name, int $depth = 0): array
    {
        if ($depth >= 10) {
            return [];
        }

        foreach (self::getRecords($nameserver, $name, DNS_CNAME) as $cname) {
            $target       = $cname->target();
            $targetServer = self::getNameserver($target);
            $txtRecords   = self::getRecords($targetServer, $target, DNS_TXT);

            if ($txtRecords !== []) {
                return $txtRecords;
            }

            $txtRecords = self::followCname($targetServer, $target, $depth + 1);

            if ($txtRecords !== []) {
                return $txtRecords;
            }
        }

        return [];
    }

    public static function getNameserver(string $domain): string
    {
        return self::getNameservers($domain)[0] ?? self::DEFAULT_NAMESERVER;
    }

    /**
     * All authoritative nameservers for $domain, found by walking up the zone
     * hierarchy until NS records appear (e.g. certtest.oa1.net → oa1.net).
     *
     * @return string[]
     */
    public static function getNameservers(string $domain): array
    {
        $dnsResolver = new Dns();
        $parts       = explode('.', $domain);

        for ($i = 0; $i < count($parts) - 1; $i++) {
            $candidate = implode('.', array_slice($parts, $i));
            try {
                $result = $dnsResolver->getRecords($candidate, DNS_NS);
                if (!empty($result)) {
                    return array_map(fn($r) => $r->target(), $result);
                }
            } catch (\Throwable) {
                // No NS at this level; try parent zone.
            }
        }

        return [self::DEFAULT_NAMESERVER];
    }

    /**
     * TXT records at _acme-challenge.{domain} queried from every authoritative NS,
     * following a CNAME when the name has no TXT records of its own.
     *
     * The TTL is the highest one served for the record set, or 0 when the
     * nameserver returned nothing. It bounds how long a resolver in front of
     * the CA may keep serving a previous value.
     *
     * @return array<array{ns: string, ip: string, found: string[], ttl: int}>
     */
    public static function lookupTxt(string $domain): array
    {
        $results = [];

        foreach (self::getNameservers($domain) as $ns) {
            try {
                $ip      = gethostbyname($ns);
                $records = self::getRecords($ns, '_acme-challenge.' . $domain, DNS_TXT)
                    ?: self::followCname($ns, '_acme-challenge.' . $domain);
                $found     = array_map(fn($r) => $r->txt(), $records);
                $ttls      = array_map(fn($r) => (int) $r->ttl(), $records);
                $results[] = [
                    'ns'    => $ns,
                    'ip'    => $ip !== $ns ? $ip : 'unresolved',
                    'found' => $found,
                    'ttl'   => $ttls === [] ? 0 : max($ttls),
                ];
            } catch (\Throwable) {
                $results[] = ['ns' => $ns, 'ip' => 'unresolved', 'found' => [], 'ttl' => 0];
            }
        }

        return $results;
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
