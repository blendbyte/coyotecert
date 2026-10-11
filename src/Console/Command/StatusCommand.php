<?php

declare(strict_types=1);

namespace CoyoteCert\Console\Command;

use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'status', description: 'Show the status of a stored certificate (exit code 1 when missing or expired)')]
class StatusCommand extends CoyoteCommand
{
    protected function configure(): void
    {
        $this
            ->addOption('identifier', 'i', InputOption::VALUE_REQUIRED, 'Primary identifier of the certificate to inspect')
            ->addOption('storage', 's', InputOption::VALUE_REQUIRED, 'Certificate storage directory', './certs')
            ->addOption('key-type', null, InputOption::VALUE_REQUIRED, 'Key type to look up: ' . self::KEY_TYPES . ' (default: every stored key type)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io         = new SymfonyStyle($input, $output);
        $identifier = $input->getOption('identifier');
        $storage    = $input->getOption('storage');

        if ($identifier === null) {
            return $this->invalid($io, '--identifier is required.');
        }

        try {
            $keyType = $input->getOption('key-type') !== null ? $this->parseKeyType($input->getOption('key-type')) : null;
        } catch (\InvalidArgumentException $e) {
            return $this->invalid($io, $e->getMessage());
        }

        $certs = $this->findCertificates(new FilesystemStorage($storage), $identifier, $keyType);

        if ($certs === []) {
            return $this->fail($io, sprintf('No certificate found for %s in %s.', $identifier, $storage));
        }

        foreach ($certs as $cert) {
            $this->renderStatus($io, $cert, $storage);
        }

        // Non-zero when any shown certificate has expired, so monitoring can act on the exit code
        $expired = array_filter($certs, static fn(StoredCertificate $cert): bool => $cert->isExpired());

        return $expired === [] ? Command::SUCCESS : Command::FAILURE;
    }

    private function renderStatus(SymfonyStyle $io, StoredCertificate $cert, string $storagePath): void
    {
        [$icon, $status, $style] = $this->expiryStatus($cert);

        try {
            $sans = $cert->sans();
        } catch (CryptoException) {
            $sans = [];
        }

        $io->newLine();
        $io->writeln(sprintf(
            ' <%s;options=bold>%s</> <options=bold>%s</>',
            $style,
            $icon,
            OutputFormatter::escape(implode(', ', $cert->domains)),
        ));
        $io->newLine();

        $this->details($io, [
            'Status'   => [$status, $style],
            'Expires'  => [sprintf('%s (%d days remaining)', $cert->expiresAt->format('M j, Y'), $cert->remainingDays()), $style],
            'Issued'   => $cert->issuedAt->format('M j, Y'),
            'SANs'     => implode(', ', $sans ?: $cert->domains),
            'Key type' => $cert->keyType->label(),
            'Storage'  => $storagePath,
        ]);
    }
}
