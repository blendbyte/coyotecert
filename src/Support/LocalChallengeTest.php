<?php

declare(strict_types=1);

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\DomainValidationException;
use CoyoteCert\Interfaces\HttpClientInterface;
use Psr\Http\Client\ClientExceptionInterface;
use RuntimeException;
use Spatie\Dns\Dns;
use Spatie\Dns\Records\CNAME;
use Spatie\Dns\Records\TXT;

class LocalChallengeTest
{
    private const DEFAULT_NAMESERVER = 'dns.google.com';

    public static function http(
        string $domain,
        string $token,
        string $keyAuthorization,
        HttpClientInterface $httpClient,
    ): void {
        // IPv6 identifiers (RFC 8738) need brackets in a URL
        $host = filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $domain . ']' : $domain;
        $url  = 'http://' . $host . '/.well-known/acme-challenge/' . $token;

        // Redirects are followed here, the way the CA does: at most 10, and only to http/https on
        // ports 80 and 443. Following anything else would let whoever controls the site point
        // this (often privileged) server at internal services.
        for ($redirects = 0; ; $redirects++) {
            try {
                $response = $httpClient->get($url);
            } catch (AcmeException|ClientExceptionInterface $e) {
                throw new DomainValidationException(
                    sprintf('The local HTTP challenge test for %s could not connect: %s', $domain, $e->getMessage()),
                    previous: $e,
                );
            }

            $location = $response->getHeaderLine('location');

            if ($redirects >= 10 || $location === '' || !in_array($response->getHttpResponseCode(), [301, 302, 303, 307, 308], true)) {
                break;
            }

            $url    = self::resolveRedirect($url, $location);
            $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
            $port   = parse_url($url, PHP_URL_PORT) ?? ($scheme === 'https' ? 443 : 80);

            if (!in_array($scheme, ['http', 'https'], true) || !in_array($port, [80, 443], true)) {
                throw new DomainValidationException(sprintf(
                    'The local HTTP challenge test for %s was redirected to %s, which the CA does not follow '
                    . '(only http and https on ports 80 and 443).',
                    $domain,
                    $url,
                ));
            }
        }

        if (trim($response->rawBody()) === $keyAuthorization) {
            return;
        }

        throw DomainValidationException::localHttpChallengeTestFailed(
            $domain,
            (string) $response->getHttpResponseCode(),
        );
    }

    /** Resolve a Location header (absolute, protocol-relative or relative) against the current URL. */
    private static function resolveRedirect(string $current, string $location): string
    {
        if (preg_match('~^[a-z][a-z0-9+.-]*:~i', $location)) {
            return $location;
        }

        $scheme = (string) parse_url($current, PHP_URL_SCHEME);

        if (str_starts_with($location, '//')) {
            return $scheme . ':' . $location;
        }

        $authority = $scheme . '://' . parse_url($current, PHP_URL_HOST)
            . (($port = parse_url($current, PHP_URL_PORT)) !== null ? ':' . $port : '');

        if (str_starts_with($location, '/')) {
            return $authority . $location;
        }

        $path = (string) parse_url($current, PHP_URL_PATH);

        return $authority . substr($path, 0, (int) strrpos($path, '/') + 1) . $location;
    }

    public static function dns(string $domain, string $name, string $value): void
    {
        $challenge   = sprintf('%s.%s', $name, $domain);
        $nameservers = self::getNameservers($domain);

        // All authoritative nameservers must have the record: ACME validators check each one.
        foreach ($nameservers as $nameserver) {
            $foundTxt    = [];
            $lookupError = null;

            try {
                $txtRecords = self::txtRecords($nameserver, $challenge);
                $foundTxt   = array_map(static fn(TXT $r): string => $r->txt(), $txtRecords);

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

    /** @param list<TXT> $records */
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
     * @return list<TXT>
     */
    private static function followCname(string $nameserver, string $name, int $depth = 0): array
    {
        if ($depth >= 10) {
            return [];
        }

        foreach (self::cnameRecords($nameserver, $name) as $cname) {
            $target       = $cname->target();
            $targetServer = self::getNameserver($target);
            $txtRecords   = self::txtRecords($targetServer, $target);

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
                $records = self::txtRecords($ns, '_acme-challenge.' . $domain)
                    ?: self::followCname($ns, '_acme-challenge.' . $domain);
                $found     = array_map(static fn(TXT $r): string => $r->txt(), $records);
                $ttls      = array_map(static fn(TXT $r): int => (int) $r->ttl(), $records);
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

    /** @return list<TXT> */
    private static function txtRecords(string $nameserver, string $name): array
    {
        return array_values(array_filter(self::getRecords($nameserver, $name, DNS_TXT), static fn($r): bool => $r instanceof TXT));
    }

    /** @return list<CNAME> */
    private static function cnameRecords(string $nameserver, string $name): array
    {
        return array_values(array_filter(self::getRecords($nameserver, $name, DNS_CNAME), static fn($r): bool => $r instanceof CNAME));
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
