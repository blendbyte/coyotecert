<?php

namespace CoyoteCert\Console\Command;

use CoyoteCert\Challenge\Http01Handler;
use CoyoteCert\Console\DnsHandlerResolver;
use CoyoteCert\Console\ProviderResolver;
use CoyoteCert\CoyoteCert;
use CoyoteCert\Exceptions\AuthException;
use CoyoteCert\Exceptions\RateLimitException;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Logger\ConsoleLogger;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'issue', description: 'Issue or renew a TLS certificate')]
class IssueCommand extends CoyoteCommand
{
    private const PROVIDERS = 'letsencrypt, letsencrypt-staging, zerossl, google, sslcom';

    protected function configure(): void
    {
        $this
            ->addOption('identifier', 'i', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Identifier(s) to include on the certificate (domain names, wildcards)')
            ->addOption('email', 'e', InputOption::VALUE_REQUIRED, 'Contact email for the ACME account')
            ->addOption('webroot', 'w', InputOption::VALUE_REQUIRED, 'Webroot path for HTTP-01 challenge (.well-known/acme-challenge will be written here)')
            ->addOption('dns', null, InputOption::VALUE_REQUIRED, 'DNS provider for DNS-01 challenge: cloudflare, hetzner, digitalocean, cloudns, route53, exec')
            ->addOption('dns-propagation-timeout', null, InputOption::VALUE_REQUIRED, 'Seconds to wait for DNS propagation before submitting the challenge (default: 60)')
            ->addOption('dns-propagation-delay', null, InputOption::VALUE_REQUIRED, 'Settle delay in seconds after the propagation check, letting resolver caches expire before validation (default: 60)')
            ->addOption('dns-skip-propagation', null, InputOption::VALUE_NONE, 'Skip the post-deploy DNS propagation check (use for split-horizon or internal DNS)')
            ->addOption('provider', 'p', InputOption::VALUE_REQUIRED, 'CA to use: ' . self::PROVIDERS)
            ->addOption('storage', 's', InputOption::VALUE_REQUIRED, 'Directory to store certificates and account keys', './certs')
            ->addOption('days', null, InputOption::VALUE_REQUIRED, 'Days before expiry to trigger renewal (default: the CA\'s ARI window, or when a third of the lifetime remains)')
            ->addOption('key-type', null, InputOption::VALUE_REQUIRED, 'Certificate key type: ' . self::KEY_TYPES, 'ec256')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Force issuance even if the certificate is still valid')
            ->addOption('skip-caa', null, InputOption::VALUE_NONE, 'Skip CAA DNS pre-check')
            ->addOption('skip-local-test', null, InputOption::VALUE_NONE, 'Skip the pre-flight HTTP self-test')
            ->addOption('zerossl-key', null, InputOption::VALUE_REQUIRED, 'ZeroSSL API key for automatic EAB provisioning (or ZEROSSL_API_KEY)')
            ->addOption('eab-kid', null, InputOption::VALUE_REQUIRED, 'EAB key ID for Google Trust Services, SSL.com, or pre-provisioned ZeroSSL (or ACME_EAB_KID)')
            ->addOption('eab-hmac', null, InputOption::VALUE_REQUIRED, 'EAB HMAC key (or ACME_EAB_HMAC)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io          = new SymfonyStyle($input, $output);
        $identifiers = $input->getOption('identifier');
        $webroot     = $input->getOption('webroot');
        $dnsProvider = $input->getOption('dns');
        $provider    = $input->getOption('provider');

        if (empty($identifiers)) {
            return $this->invalid($io, 'No identifiers specified. Use --identifier example.com (repeatable for SANs).');
        }

        if (($dnsProvider === null) === ($webroot === null)) {
            return $this->invalid($io, 'Pass exactly one of --webroot (HTTP-01) or --dns (DNS-01).');
        }

        if ($provider === null) {
            return $this->invalid($io, '--provider is required. Supported: ' . self::PROVIDERS . '.');
        }

        try {
            $acmeProvider = ProviderResolver::resolve(
                $provider,
                zeroSslKey: $this->secret($input, 'zerossl-key', 'ZEROSSL_API_KEY'),
                eabKid: $this->secret($input, 'eab-kid', 'ACME_EAB_KID'),
                eabHmac: $this->secret($input, 'eab-hmac', 'ACME_EAB_HMAC'),
            );
            $keyType          = $this->parseKeyType($input->getOption('key-type'));
            $days             = $this->intOption($input, 'days', min: 1);
            $challengeHandler = $dnsProvider !== null
                ? $this->dnsHandler($input, $dnsProvider)
                : new Http01Handler($webroot);
        } catch (\InvalidArgumentException $e) {
            return $this->invalid($io, $e->getMessage());
        }

        $storagePath = $input->getOption('storage');
        $coyote      = CoyoteCert::with($acmeProvider)
            ->storage(new FilesystemStorage($storagePath))
            ->identifiers($identifiers)
            ->challenge($challengeHandler)
            ->keyType($keyType);

        if ($output->isVerbose()) {
            $coyote->logger(new ConsoleLogger($output));
        }

        if ($input->getOption('email')) {
            $coyote->email($input->getOption('email'));
        }

        if ($input->getOption('skip-caa')) {
            $coyote->skipCaaCheck();
        }

        if ($input->getOption('skip-local-test')) {
            $coyote->skipLocalTest();
        }

        $io->writeln(sprintf(
            ' Requesting certificate for <info>%s</info> via <comment>%s</comment>...',
            OutputFormatter::escape($identifiers[0]),
            OutputFormatter::escape($acmeProvider->getDisplayName()),
        ));

        try {
            [$cert, $wasIssued] = $this->performIssue($coyote, $input->getOption('force'), $days);
        } catch (RateLimitException $e) {
            $retryAfter = $e->getRetryAfter();

            return $this->fail($io, 'Rate limit reached: too many certificate requests recently.', $retryAfter !== null
                ? sprintf('Retry after %d seconds.', $retryAfter)
                : 'Check your CA dashboard for rate limit details.');
        } catch (AuthException $e) {
            return $this->fail($io, 'Authentication failed.', $e->getMessage());
        } catch (\Throwable $e) {
            return $this->fail($io, 'Certificate issuance failed.', $e->getMessage());
        }

        $this->renderSuccess($io, $cert, $storagePath, $acmeProvider->getDisplayName(), $wasIssued);

        return Command::SUCCESS;
    }

    /**
     * @return array{StoredCertificate, bool}
     */
    protected function performIssue(CoyoteCert $builder, bool $force, ?int $days): array
    {
        $wasIssued = false;
        $builder->onIssued(function () use (&$wasIssued): void {
            $wasIssued = true;
        });
        $cert = $force ? $builder->issue() : $builder->issueOrRenew($days);

        return [$cert, $wasIssued];
    }

    private function dnsHandler(InputInterface $input, string $dnsProvider): ChallengeHandlerInterface
    {
        $handler = DnsHandlerResolver::resolve($dnsProvider);

        if (($timeout = $this->intOption($input, 'dns-propagation-timeout')) !== null) {
            $handler = $handler->propagationTimeout($timeout);
        }

        if (($delay = $this->intOption($input, 'dns-propagation-delay')) !== null) {
            $handler = $handler->propagationDelay($delay);
        }

        return $input->getOption('dns-skip-propagation') ? $handler->skipPropagationCheck() : $handler;
    }

    private function renderSuccess(SymfonyStyle $io, StoredCertificate $cert, string $storagePath, string $provider, bool $wasIssued): void
    {
        $io->newLine();
        $io->writeln($wasIssued
            ? ' <fg=green;options=bold>✓</> <options=bold>Certificate issued successfully</>'
            : ' <fg=blue;options=bold>→</> <options=bold>Certificate is still valid, no renewal needed</>');
        $io->newLine();

        [, , $style] = $this->expiryStatus($cert);

        $this->details($io, [
            'Identifier(s)' => implode(', ', $cert->domains),
            'Provider'      => $provider,
            'Key type'      => $cert->keyType->label(),
            'Expires'       => [sprintf('%s (%d days)', $cert->expiresAt->format('M j, Y'), $cert->remainingDays()), $style],
            'Storage'       => $storagePath,
        ]);
    }
}
