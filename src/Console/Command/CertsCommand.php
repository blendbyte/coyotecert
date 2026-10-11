<?php

namespace CoyoteCert\Console\Command;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'certs', description: 'List all stored certificates')]
class CertsCommand extends CoyoteCommand
{
    protected function configure(): void
    {
        $this
            ->addOption('storage', 's', InputOption::VALUE_REQUIRED, 'Directory where certificates are stored', './certs');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io          = new SymfonyStyle($input, $output);
        $storagePath = (string) $input->getOption('storage');
        $dir         = rtrim($storagePath, '/') . '/';

        if (!is_dir($dir)) {
            return $this->fail($io, sprintf('Storage directory not found: %s', $storagePath));
        }

        $certs = $this->loadCerts($dir, $storagePath);

        if ($certs === []) {
            $io->writeln(sprintf(' No certificates found in %s', OutputFormatter::escape($storagePath)));

            return Command::SUCCESS;
        }

        $io->newLine();
        $io->writeln(sprintf(
            ' <fg=gray>%d certificate%s in %s</>',
            count($certs),
            count($certs) === 1 ? '' : 's',
            OutputFormatter::escape($storagePath),
        ));

        $table = (new Table($output))->setStyle('compact');

        foreach ($certs as $cert) {
            [$icon, $status, $style] = $this->expiryStatus($cert);

            $table->addRow([
                sprintf('  <%s;options=bold>%s</>', $style, $icon),
                OutputFormatter::escape(implode(', ', $cert->domains)),
                sprintf('<fg=gray>%s</>', $cert->keyType->label()),
                sprintf('<%s>%s</>', $style, $status),
                sprintf('<%s>%s</>', $style, $cert->expiresAt->format('M j, Y')),
            ]);
        }

        $table->render();
        $io->newLine();

        return Command::SUCCESS;
    }

    /**
     * @return list<StoredCertificate>
     */
    private function loadCerts(string $dir, string $storagePath): array
    {
        $keyTypeValues = implode('|', array_map(fn(KeyType $k) => preg_quote($k->value, '/'), KeyType::cases()));
        $pattern       = '/^(.+)\.(' . $keyTypeValues . ')\.cert\.json$/';
        $fs            = new FilesystemStorage($storagePath);
        $certs         = [];

        foreach (glob($dir . '*.cert.json') ?: [] as $file) {
            // {domain slug}.{key type}.cert.json
            if (preg_match($pattern, basename($file), $m) && ($cert = $fs->getCertificate($m[1], KeyType::from($m[2]))) !== null) {
                $certs[] = $cert;
            }
        }

        usort($certs, fn(StoredCertificate $a, StoredCertificate $b) => $a->expiresAt <=> $b->expiresAt);

        return $certs;
    }
}
