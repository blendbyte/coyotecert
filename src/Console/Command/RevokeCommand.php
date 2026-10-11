<?php

declare(strict_types=1);

namespace CoyoteCert\Console\Command;

use CoyoteCert\Console\ProviderResolver;
use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\RevocationReason;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\AuthException;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'revoke', description: 'Revoke a stored certificate')]
class RevokeCommand extends CoyoteCommand
{
    private const REASONS = 'unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessationofoperation, certificatehold, privilegewithdrawn, aacompromise';

    protected function configure(): void
    {
        $this
            ->addOption('identifier', 'i', InputOption::VALUE_REQUIRED, 'Primary identifier of the certificate to revoke')
            ->addOption('provider', 'p', InputOption::VALUE_REQUIRED, 'CA the certificate was issued by: letsencrypt, letsencrypt-staging, zerossl, google, sslcom')
            ->addOption('storage', 's', InputOption::VALUE_REQUIRED, 'Directory where certificates are stored', './certs')
            ->addOption('key-type', null, InputOption::VALUE_REQUIRED, 'Key type of the certificate: ' . self::KEY_TYPES . ' (needed only when several are stored)')
            ->addOption('reason', null, InputOption::VALUE_REQUIRED, 'Revocation reason: ' . self::REASONS, 'unspecified');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io         = new SymfonyStyle($input, $output);
        $identifier = $input->getOption('identifier');
        $provider   = $input->getOption('provider');

        if ($identifier === null) {
            return $this->invalid($io, '--identifier is required.');
        }

        if ($provider === null) {
            return $this->invalid($io, '--provider is required. It must match the CA that issued the certificate.');
        }

        try {
            // Revocation is signed with the stored account key; EAB is only needed to register one
            $acmeProvider = ProviderResolver::resolve($provider, requireEab: false);
            $keyType      = $input->getOption('key-type') !== null ? $this->parseKeyType($input->getOption('key-type')) : null;
            $reason       = $this->parseReason($input->getOption('reason'));
        } catch (\InvalidArgumentException $e) {
            return $this->invalid($io, $e->getMessage());
        }

        $storagePath = $input->getOption('storage');
        $fs          = new FilesystemStorage($storagePath);
        $certs       = $this->findCertificates($fs, $identifier, $keyType);

        if ($certs === []) {
            return $this->fail($io, sprintf('No certificate found for %s in %s.', $identifier, $storagePath));
        }

        if (count($certs) > 1) {
            return $this->invalid($io, sprintf(
                'Several certificates are stored for %s (%s). Choose one with --key-type.',
                $identifier,
                implode(', ', array_map(static fn(StoredCertificate $c): string => $c->keyType->label(), $certs)),
            ));
        }

        $cert = $certs[0];

        try {
            $this->performRevoke(CoyoteCert::with($acmeProvider)->storage($fs), $cert, $reason);
        } catch (AuthException $e) {
            return $this->fail($io, 'Authentication failed.', $e->getMessage());
        } catch (AcmeException $e) {
            return $this->fail($io, 'Revocation failed.', $e->getMessage());
        }

        $io->newLine();
        $io->writeln(' <fg=green;options=bold>✓</> <options=bold>Certificate revoked</>');
        $io->newLine();

        $this->details($io, [
            'Identifier(s)' => implode(', ', $cert->domains),
            'Reason'        => $reason->name,
            'Provider'      => $acmeProvider->getDisplayName(),
            'Storage'       => $storagePath,
        ]);

        return Command::SUCCESS;
    }

    protected function performRevoke(CoyoteCert $coyote, StoredCertificate $cert, RevocationReason $reason): void
    {
        $coyote->revoke($cert, $reason);
    }

    private function parseReason(string $reason): RevocationReason
    {
        return match (strtolower($reason)) {
            'unspecified'          => RevocationReason::Unspecified,
            'keycompromise'        => RevocationReason::KeyCompromise,
            'cacompromise'         => RevocationReason::CaCompromise,
            'affiliationchanged'   => RevocationReason::AffiliationChanged,
            'superseded'           => RevocationReason::Superseded,
            'cessationofoperation' => RevocationReason::CessationOfOperation,
            'certificatehold'      => RevocationReason::CertificateHold,
            'privilegewithdrawn'   => RevocationReason::PrivilegeWithdrawn,
            'aacompromise'         => RevocationReason::AaCompromise,
            default                => throw new \InvalidArgumentException(
                sprintf('Unknown reason "%s". Supported: %s.', $reason, self::REASONS),
            ),
        };
    }
}
