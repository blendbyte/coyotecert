<?php

namespace CoyoteCert\Support;

use CoyoteCert\Exceptions\CaaException;
use Spatie\Dns\Dns;
use Spatie\Dns\Records\CAA;

class CaaChecker
{
    /** @var callable(string): CAA[] */
    private $resolver;

    /**
     * @param callable(string): CAA[]|null $resolver Injected for testing; defaults to spatie/dns.
     */
    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver
            ?? static fn(string $domain): array => (new Dns())->getRecords($domain, 'CAA');
    }

    /**
     * Check that $caIdentifiers are permitted by CAA records for every domain.
     * A missing or empty $caIdentifiers list means "skip" (unknown/custom CA).
     *
     * @param string[] $domains
     * @param string[] $caIdentifiers
     * @throws CaaException
     */
    public function check(array $domains, array $caIdentifiers): void
    {
        if (empty($caIdentifiers)) {
            return;
        }

        foreach ($domains as $domain) {
            $this->checkDomain($domain, $caIdentifiers);
        }
    }

    /**
     * @param string[] $caIdentifiers
     * @throws CaaException
     */
    private function checkDomain(string $domain, array $caIdentifiers): void
    {
        $isWildcard = str_starts_with($domain, '*.');
        $lookup     = $isWildcard ? substr($domain, 2) : $domain;

        $records = $this->fetchCaaRecords($lookup);

        if (empty($records)) {
            return; // No CAA records anywhere in the tree → open policy
        }

        // Wildcards must have an issuewild authorisation; fall back to issue if absent.
        $tag        = $isWildcard ? 'issuewild' : 'issue';
        $tagRecords = array_values(array_filter($records, static fn(CAA $r) => $r->tag() === $tag));

        if ($isWildcard && empty($tagRecords)) {
            $tagRecords = array_values(array_filter($records, static fn(CAA $r) => $r->tag() === 'issue'));
        }

        if (empty($tagRecords)) {
            return; // Only iodef or unknown tags — no restriction on issuance
        }

        foreach ($tagRecords as $record) {
            // Strip optional surrounding quotes; drop any parameter extensions after ';'
            $rawValue = trim((string) $record->value(), '"');
            $caHost   = strtolower(trim(explode(';', $rawValue)[0]));

            foreach ($caIdentifiers as $identifier) {
                if ($caHost === strtolower(trim($identifier))) {
                    return; // At least one record permits the CA
                }
            }
        }

        throw new CaaException(sprintf(
            'CAA records for "%s" do not permit issuance by this CA (expected one of: %s).',
            $lookup,
            implode(', ', $caIdentifiers),
        ));
    }

    /**
     * Walk up the DNS tree looking for CAA records, stopping at the second label.
     *
     * @return CAA[]
     */
    private function fetchCaaRecords(string $domain): array
    {
        $labels = explode('.', $domain);

        while (count($labels) >= 2) {
            $check = implode('.', $labels);
            /** @var CAA[] $records */
            $records = ($this->resolver)($check);

            if (!empty($records)) {
                return $records;
            }

            array_shift($labels);
        }

        return [];
    }
}
