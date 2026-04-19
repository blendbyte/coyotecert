<?php

namespace CoyoteCert\Console\Command;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function Termwind\render;

#[AsCommand(name: 'status', description: 'Show the status of a stored certificate')]
class StatusCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('identifier', 'i', InputOption::VALUE_REQUIRED, 'Primary identifier of the certificate to inspect')
            ->addOption('storage', 's', InputOption::VALUE_REQUIRED, 'Certificate storage directory', './certs')
            ->addOption('key-type', null, InputOption::VALUE_REQUIRED, 'Key type to look up: ec256, ec384, rsa2048, rsa4096', 'ec256');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $identifier = $input->getOption('identifier');
        $storage    = $input->getOption('storage');

        if ($identifier === null) {
            render(<<<HTML
                    <div class="mt-1 mb-1 ml-2">
                        <span class="text-red-500 font-bold">✗</span>
                        <span class="ml-1 text-red-500">--identifier is required.</span>
                    </div>
                HTML);

            return Command::FAILURE;
        }

        try {
            $keyType = $this->resolveKeyType($input->getOption('key-type'));
        } catch (\InvalidArgumentException $e) {
            render(sprintf(
                <<<HTML
                    <div class="mt-1 mb-1 ml-2">
                        <span class="text-red-500 font-bold">✗</span>
                        <span class="ml-1 text-red-500">%s</span>
                    </div>
                    HTML,
                $e->getMessage(),
            ));

            return Command::FAILURE;
        }

        $fs   = new FilesystemStorage($storage);
        $cert = $fs->getCertificate($identifier, $keyType);

        if ($cert === null) {
            render(sprintf(
                <<<HTML
                    <div class="mt-1 mb-1 ml-2">
                        <span class="text-yellow-500 font-bold">–</span>
                        <span class="ml-1">No certificate found for <span class="font-bold">%s</span> in %s</span>
                    </div>
                    HTML,
                $identifier,
                $storage,
            ));

            return Command::FAILURE;
        }

        $this->renderStatus($cert, $storage);

        return Command::SUCCESS;
    }

    private function renderStatus(StoredCertificate $cert, string $storagePath): void
    {
        $days    = $cert->remainingDays();
        $expired = $cert->isExpired();

        [$statusIcon, $statusText, $statusColor] = match (true) {
            $expired    => ['✗', 'Expired', 'text-red-500'],
            $days <= 7  => ['!', 'Expiring soon', 'text-red-500'],
            $days <= 30 => ['!', 'Renewal due', 'text-yellow-500'],
            default     => ['✓', 'Valid', 'text-green-500'],
        };

        $daysColor      = $expired || $days <= 7 ? 'text-red-500' : ($days <= 30 ? 'text-yellow-500' : 'text-green-400');
        $expiresDate    = $cert->expiresAt->format('M j, Y');
        $expiresStr     = sprintf('%s (%d days remaining)', $expiresDate, $days);
        $issuedDate     = $cert->issuedAt->format('M j, Y');
        $identifiersStr = implode(', ', $cert->domains);
        try {
            $sans = $cert->sans();
        } catch (\CoyoteCert\Exceptions\CryptoException) {
            $sans = [];
        }
        $sansStr  = empty($sans) ? $identifiersStr : implode(', ', $sans);
        $keyLabel = match ($cert->keyType) {
            KeyType::EC_P256  => 'EC P-256',
            KeyType::EC_P384  => 'EC P-384',
            KeyType::RSA_2048 => 'RSA 2048',
            KeyType::RSA_4096 => 'RSA 4096',
        };

        render(sprintf(
            <<<HTML
                <div class="mt-1 mb-1">
                    <div class="ml-2">
                        <span class="%s font-bold">%s</span>
                        <span class="ml-1 font-bold">%s</span>
                        <span class="ml-1 text-gray-500">— %s</span>
                    </div>
                    <table class="mt-1 ml-4">
                        <tr>
                            <td class="text-gray-500 pr-4">Status</td>
                            <td class="%s">%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Expires</td>
                            <td class="%s">%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Issued</td>
                            <td>%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">SANs</td>
                            <td>%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Key type</td>
                            <td>%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Storage</td>
                            <td>%s</td>
                        </tr>
                    </table>
                </div>
                HTML,
            $statusColor,
            $statusIcon,
            $identifiersStr,
            $storagePath,
            $statusColor,
            $statusText,
            $daysColor,
            $expiresStr,
            $issuedDate,
            $sansStr,
            $keyLabel,
            $storagePath,
        ));
    }

    private function resolveKeyType(string $type): KeyType
    {
        return match (strtolower($type)) {
            'ec256', 'ec-p256', 'p256' => KeyType::EC_P256,
            'ec384', 'ec-p384', 'p384' => KeyType::EC_P384,
            'rsa2048'                  => KeyType::RSA_2048,
            'rsa4096'                  => KeyType::RSA_4096,
            default                    => throw new \InvalidArgumentException(
                sprintf('Unknown key type "%s". Supported: ec256, ec384, rsa2048, rsa4096.', $type),
            ),
        };
    }
}
