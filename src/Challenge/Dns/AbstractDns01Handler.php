<?php

declare(strict_types=1);

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Support\LocalChallengeTest;
use Psr\Log\LoggerInterface;

/**
 * Base class for dns-01 challenge handlers.
 *
 * Extend this class, implement deploy() and cleanup(), and the handler will
 * automatically respond to the dns-01 challenge type. Deploy a TXT record at
 * _acme-challenge.{domain} with $keyAuthorization as the value; remove it in
 * cleanup().
 *
 * After deploy(), call awaitPropagation($domain, $keyAuthorization) to register
 * the value and wait until it is visible on the domain's authoritative
 * nameservers. When CoyoteCert drives the handler, that wait is deferred until
 * every record of the order has been written, so a wildcard and its base name
 * never leave a half-complete TXT record set published while the CA (or any
 * resolver in front of it) is free to cache it. The check is enabled by default
 * and can be disabled with skipPropagationCheck().
 *
 * Example:
 *
 *   class MyDns01Handler extends AbstractDns01Handler
 *   {
 *       public function deploy(string $domain, string $token, string $keyAuth): void
 *       {
 *           MyDns::setTxt($this->challengeName($domain), $keyAuth);
 *           $this->awaitPropagation($domain, $keyAuth);
 *       }
 *
 *       public function cleanup(string $domain, string $token): void
 *       {
 *           MyDns::deleteTxt($this->challengeName($domain));
 *       }
 *   }
 *
 *   // Disable check for internal / split-horizon DNS:
 *   $handler = new MyDns01Handler()->skipPropagationCheck();
 *
 *   // Extend the poll window:
 *   $handler = new MyDns01Handler()->propagationTimeout(120);
 *
 *   // Change the settle delay applied after the records are confirmed:
 *   $handler = new MyDns01Handler()->propagationDelay(60);
 */
abstract class AbstractDns01Handler implements ChallengeHandlerInterface
{
    private bool             $propagationCheck        = true;
    private int              $propagationTimeout      = 60;
    private int              $propagationPollInterval = 5;
    private int              $propagationDelaySecs    = 60;
    private bool             $purgeExistingOnDeploy   = true;
    private ?LoggerInterface $logger                  = null;

    /** @var array<string, true> Tracks domains already purged this handler instance to avoid wiping sibling challenges (e.g. wildcard + base). */
    private array $purgeDone = [];

    /** @var array<string, list<string>> domain => TXT values deployed but not yet confirmed on the nameservers. */
    private array $pending = [];

    /** True while a deploy batch is open; propagation is then confirmed once, after the last record is written. */
    private bool $batching = false;

    final public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::DNS;
    }

    /**
     * Disable the post-deploy DNS propagation check.
     *
     * Use this for internal or split-horizon DNS where the authoritative
     * nameservers are not reachable from the machine running CoyoteCert.
     */
    public function skipPropagationCheck(): static
    {
        $clone                   = clone $this;
        $clone->propagationCheck = false;

        return $clone;
    }

    /**
     * Set the maximum number of seconds to wait for the TXT record to appear
     * on the authoritative nameservers. Defaults to 60.
     */
    public function propagationTimeout(int $seconds): static
    {
        $clone                     = clone $this;
        $clone->propagationTimeout = max(1, $seconds);

        return $clone;
    }

    /**
     * Set the settle delay applied once the records are confirmed on the
     * authoritative nameservers (or instead of the check when it is disabled).
     * Defaults to 60 seconds.
     *
     * Authoritative visibility is not resolver visibility: the CA validates
     * through caching recursors and anycast secondaries that may still hold the
     * pre-update answer for up to the record TTL. Waiting here lets those
     * expire, so the delay should be at least the TTL of the _acme-challenge
     * record. Pass 0 to disable.
     */
    public function propagationDelay(int $seconds): static
    {
        $clone                       = clone $this;
        $clone->propagationDelaySecs = max(0, $seconds);

        return $clone;
    }

    /**
     * Disable the automatic deletion of existing _acme-challenge TXT records
     * before deploying a new one.
     *
     * By default, deploy() removes any stale records left by a previous failed
     * run so they cannot confuse the CA's validation. Call this to preserve them.
     * Has no effect on providers that do not implement deleteExistingRecords()
     * (e.g. ShellDns01Handler).
     */
    public function keepExistingRecords(): static
    {
        $clone                        = clone $this;
        $clone->purgeExistingOnDeploy = false;

        return $clone;
    }

    public function withLogger(LoggerInterface $logger): static
    {
        $clone         = clone $this;
        $clone->logger = $logger;

        return $clone;
    }

    /**
     * The TXT record name for the given domain.
     * Always '_acme-challenge.{domain}'.
     */
    protected function challengeName(string $domain): string
    {
        return '_acme-challenge.' . $domain;
    }

    /**
     * Walk the public-suffix candidates for zone auto-detection.
     *
     * sub.example.com → ['sub.example.com', 'example.com']
     * example.com     → ['example.com']
     *
     * @return list<string>
     */
    protected function zoneCandidates(string $domain): array
    {
        $parts      = explode('.', $domain);
        $candidates = [];

        for ($i = 0; $i < count($parts) - 1; $i++) {
            $candidates[] = implode('.', array_slice($parts, $i));
        }

        return $candidates;
    }

    /**
     * The relative TXT record name within a zone.
     *
     * For providers that require a label relative to the zone (Hetzner,
     * DigitalOcean, ClouDNS) rather than the FQDN (Cloudflare, Route53).
     *
     * example.com     in zone example.com → '_acme-challenge'
     * sub.example.com in zone example.com → '_acme-challenge.sub'
     */
    protected function relativeRecordName(string $domain, string $zoneName): string
    {
        if ($domain === $zoneName) {
            return '_acme-challenge';
        }

        return '_acme-challenge.' . substr($domain, 0, -(strlen($zoneName) + 1));
    }

    /**
     * Delete any pre-existing _acme-challenge TXT records for $domain before
     * deploying the new one. Override this in concrete handlers that support
     * record enumeration via their provider API.
     */
    protected function deleteExistingRecords(string $domain): void {}

    /**
     * Call this at the start of deploy() to conditionally purge stale records.
     *
     * Purges at most once per domain per handler instance. This prevents the
     * second deploy() call for the same domain (e.g. wildcard + base both
     * requiring _acme-challenge.example.com) from wiping the first challenge.
     */
    final protected function maybePurgeExisting(string $domain): void
    {
        if ($this->purgeExistingOnDeploy && !isset($this->purgeDone[$domain])) {
            $this->deleteExistingRecords($domain);
            $this->purgeDone[$domain] = true;
        }
    }

    /**
     * Open a deploy batch: awaitPropagation() only registers the deployed value
     * and returns, so every record of the order is written before any DNS check
     * runs. Closed by awaitDeployedRecords(). Called by CoyoteCert around the
     * deploy loop.
     */
    final public function beginDeployBatch(): void
    {
        $this->batching  = true;
        $this->pending   = [];
        $this->purgeDone = []; // a new order may reuse this handler: purge stale records again
    }

    /**
     * Close the deploy batch: wait until every deployed value is visible on the
     * authoritative nameservers, then apply the settle delay once.
     */
    final public function awaitDeployedRecords(): void
    {
        $this->batching = false;
        $this->confirmPending();
    }

    /**
     * Register the deployed TXT value and wait for it to become visible on the
     * domain's authoritative nameservers, then apply the settle delay.
     *
     * Call this at the end of deploy() after the API call succeeds. Inside a
     * deploy batch the wait is deferred to awaitDeployedRecords() so sibling
     * challenges sharing one _acme-challenge name are confirmed together.
     *
     * Fails open on timeout or DNS resolution errors: the ACME server
     * determines the final validation outcome.
     */
    protected function awaitPropagation(string $domain, string $keyAuthorization): void
    {
        $this->pending[$domain][] = $keyAuthorization;

        if (!$this->batching) {
            $this->confirmPending();
        }
    }

    private function confirmPending(): void
    {
        if ($this->pending === []) {
            return;
        }

        if ($this->propagationCheck) {
            foreach ($this->pending as $domain => $keyAuthorizations) {
                $this->pollForTxtRecords($domain, $keyAuthorizations);
            }
        }

        $this->pending = [];

        if ($this->propagationDelaySecs > 0) {
            sleep($this->propagationDelaySecs);
        }
    }

    /**
     * Poll the domain's authoritative nameservers until every expected
     * _acme-challenge TXT value is present, or the timeout is reached.
     *
     * Marked protected so tests can subclass and inject instant responses
     * without making real DNS queries.
     *
     * @param list<string> $keyAuthorizations
     */
    protected function pollForTxtRecords(string $domain, array $keyAuthorizations): void
    {
        $deadline = time() + $this->propagationTimeout;

        do {
            if ($this->areTxtRecordsVisible($domain, $keyAuthorizations)) {
                return;
            }

            if (time() < $deadline) {
                sleep($this->propagationPollInterval);
            }
        } while (time() < $deadline);

        // Timeout: fail open and let the ACME server decide.
    }

    /**
     * Perform a single DNS visibility check: every expected value must be
     * present on every authoritative nameserver. A partial record set means the
     * CA can still read a stale answer, so it does not count as propagated.
     *
     * Marked protected so tests can subclass and return a controlled result
     * without making real DNS queries.
     *
     * @param list<string> $keyAuthorizations
     */
    protected function areTxtRecordsVisible(string $domain, array $keyAuthorizations): bool
    {
        $allVisible = true;
        $highestTtl = 0;

        foreach ($this->lookupTxt($domain) as $result) {
            $missing    = array_diff($keyAuthorizations, $result['found']);
            $highestTtl = max($highestTtl, $result['ttl']);
            $allVisible = $allVisible && $missing === [];

            $this->logger?->debug(sprintf(
                'DNS propagation check: %s (%s) → _acme-challenge.%s TXT = %s%s%s',
                $result['ns'],
                $result['ip'],
                $domain,
                empty($result['found'])
                    ? '(none)'
                    : implode(', ', array_map(fn($v) => '"' . $v . '"', $result['found'])),
                $result['ttl'] > 0 ? sprintf(' (ttl %ds)', $result['ttl']) : '',
                $missing === []
                    ? ''
                    : sprintf(' (missing %d of %d)', count($missing), count($keyAuthorizations)),
            ));
        }

        if ($allVisible) {
            $this->logger?->debug(sprintf(
                'All %d TXT record(s) confirmed on all nameservers: _acme-challenge.%s',
                count($keyAuthorizations),
                $domain,
            ));
            $this->warnOnLongTtl($domain, $highestTtl);
        }

        return $allVisible;
    }

    /**
     * Warn when the challenge record outlives the settle delay.
     *
     * The CA validates through caching resolvers, and its remote perspectives
     * reuse those caches. A resolver that read the record during an earlier
     * issuance keeps serving that value for the TTL, so re-issuing the same
     * name inside that window is rejected with "Incorrect TXT record ... found"
     * no matter how cleanly the new value propagated.
     */
    private function warnOnLongTtl(string $domain, int $ttl): void
    {
        if ($this->logger === null || $ttl <= $this->propagationDelaySecs) {
            return;
        }

        $this->logger->warning(sprintf(
            '_acme-challenge.%s is served with a TTL of %ds, longer than the %ds settle delay. '
            . 'Resolvers in front of the CA can still be serving the previous value, which fails '
            . 'validation. Lower the TTL on the challenge record or raise propagationDelay().',
            $domain,
            $ttl,
            $this->propagationDelaySecs,
        ));
    }

    /**
     * Read the _acme-challenge TXT values currently served by each of the
     * domain's authoritative nameservers.
     *
     * Marked protected so tests can subclass and return canned results
     * without making real DNS queries.
     *
     * @return array<array{ns: string, ip: string, found: string[], ttl: int}>
     */
    protected function lookupTxt(string $domain): array
    {
        return LocalChallengeTest::lookupTxt($domain);
    }
}
