<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Exceptions\DomainValidationException;
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
 * After deploy(), call awaitPropagation($domain, $keyAuthorization) to wait
 * until the record is visible on the domain's authoritative nameservers before
 * returning — this is the same check the ACME server performs, so it eliminates
 * premature challenge submission. The check is enabled by default and can be
 * disabled with skipPropagationCheck().
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
 *   // Add a fixed sleep on top of (or instead of) the DNS check:
 *   $handler = new MyDns01Handler()->propagationDelay(10);
 */
abstract class AbstractDns01Handler implements ChallengeHandlerInterface
{
    private bool             $propagationCheck        = true;
    private int              $propagationTimeout      = 60;
    private int              $propagationPollInterval = 5;
    private int              $propagationDelaySecs    = 0;
    private ?LoggerInterface $logger                  = null;

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
     * Add a fixed sleep after the propagation check (or instead of it when
     * the check is disabled). Useful for providers with delayed secondary sync.
     */
    public function propagationDelay(int $seconds): static
    {
        $clone                       = clone $this;
        $clone->propagationDelaySecs = max(0, $seconds);

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
     * Wait for the _acme-challenge TXT record to appear on the domain's
     * authoritative nameservers, then apply any configured fixed delay.
     *
     * Call this at the end of deploy() after the API call succeeds.
     * Fails open on timeout or DNS resolution errors — the ACME server
     * determines the final validation outcome.
     */
    protected function awaitPropagation(string $domain, string $keyAuthorization): void
    {
        if ($this->propagationCheck) {
            $this->pollForTxtRecord($domain, $keyAuthorization);
        }

        if ($this->propagationDelaySecs > 0) {
            sleep($this->propagationDelaySecs);
        }
    }

    /**
     * Poll the domain's authoritative nameservers until the _acme-challenge
     * TXT record appears with the expected value, or the timeout is reached.
     *
     * Marked protected so tests can subclass and inject instant responses
     * without making real DNS queries.
     */
    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void
    {
        $deadline = time() + $this->propagationTimeout;

        do {
            if ($this->isTxtRecordVisible($domain, $keyAuthorization)) {
                return;
            }

            if (time() < $deadline) {
                sleep($this->propagationPollInterval);
            }
        } while (time() < $deadline);

        // Timeout: fail open and let the ACME server decide.
    }

    /**
     * Perform a single DNS TXT record visibility check.
     *
     * Marked protected so tests can subclass and return a controlled result
     * without making real DNS queries.
     */
    protected function isTxtRecordVisible(string $domain, string $keyAuthorization): bool
    {
        if ($this->logger !== null) {
            try {
                $ns = LocalChallengeTest::getNameserver($domain);
                $ip = gethostbyname($ns);
                $this->logger->debug(sprintf(
                    'DNS propagation check: querying %s (%s) for _acme-challenge.%s TXT',
                    $ns,
                    $ip !== $ns ? $ip : 'unresolved',
                    $domain,
                ));
            } catch (\Throwable) {
                $this->logger->debug(sprintf('DNS propagation check for %s (NS lookup failed)', $domain));
            }
        }

        try {
            LocalChallengeTest::dns($domain, '_acme-challenge', $keyAuthorization);
            $this->logger?->debug(sprintf('TXT record confirmed: _acme-challenge.%s is visible', $domain));

            return true;
        } catch (DomainValidationException $e) {
            $this->logger?->debug($e->getMessage());

            return false;
        }
    }
}
