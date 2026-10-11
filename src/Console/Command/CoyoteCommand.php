<?php

namespace CoyoteCert\Console\Command;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\FilesystemStorage;
use CoyoteCert\Storage\StoredCertificate;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/** Output and option helpers shared by the coyote commands. */
abstract class CoyoteCommand extends Command
{
    protected const KEY_TYPES = 'ec256, ec384, rsa2048, rsa4096';

    /**
     * Print an error to stderr and return $code (FAILURE, or INVALID for usage errors).
     * Errors still show with -q ("only errors are displayed"); only --silent hides them.
     */
    protected function fail(SymfonyStyle $io, string $message, string $detail = '', int $code = Command::FAILURE): int
    {
        $err = $io->getErrorStyle();
        $err->writeln(sprintf(' <fg=red;options=bold>✗</> <fg=red>%s</>', OutputFormatter::escape($message)), OutputInterface::VERBOSITY_QUIET);

        if ($detail !== '') {
            $err->writeln('   ' . OutputFormatter::escape($detail), OutputInterface::VERBOSITY_QUIET);
        }

        return $code;
    }

    protected function invalid(SymfonyStyle $io, string $message): int
    {
        return $this->fail($io, $message, code: Command::INVALID);
    }

    /**
     * Aligned "label  value" rows. Values are escaped; pass [value, style] to colour one.
     *
     * @param non-empty-array<string, string|array{0: string, 1: string}> $rows
     */
    protected function details(SymfonyStyle $io, array $rows): void
    {
        $width = max(array_map(strlen(...), array_keys($rows)));

        foreach ($rows as $label => $value) {
            [$text, $style] = is_array($value) ? $value : [$value, ''];
            $text           = OutputFormatter::escape($text);

            $io->writeln(sprintf(
                '   <fg=gray>%s</>  %s',
                str_pad($label, $width),
                $style !== '' ? "<{$style}>{$text}</>" : $text,
            ));
        }

        $io->newLine();
    }

    protected function parseKeyType(string $type): KeyType
    {
        return match (strtolower($type)) {
            'ec256', 'ec-p256', 'p256' => KeyType::EC_P256,
            'ec384', 'ec-p384', 'p384' => KeyType::EC_P384,
            'rsa2048'                  => KeyType::RSA_2048,
            'rsa4096'                  => KeyType::RSA_4096,
            default                    => throw new \InvalidArgumentException(
                sprintf('Unknown key type "%s". Supported: %s.', $type, self::KEY_TYPES),
            ),
        };
    }

    /**
     * Stored certificates for $identifier, of $keyType when given, otherwise of any key type.
     *
     * @return list<StoredCertificate>
     */
    protected function findCertificates(FilesystemStorage $storage, string $identifier, ?KeyType $keyType): array
    {
        return array_values(array_filter(array_map(
            static fn(KeyType $type): ?StoredCertificate => $storage->getCertificate(strtolower($identifier), $type),
            $keyType !== null ? [$keyType] : KeyType::cases(),
        )));
    }

    /** A secret from its option, falling back to an environment variable so it can stay out of argv. */
    protected function secret(InputInterface $input, string $option, string $env): ?string
    {
        $value = $input->getOption($option) ?? getenv($env);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /** @throws \InvalidArgumentException when the option is set but not a whole number */
    protected function intOption(InputInterface $input, string $option, int $min = 0): ?int
    {
        $value = $input->getOption($option);

        if ($value === null) {
            return null;
        }

        if (!is_string($value) || !ctype_digit($value) || (int) $value < $min) {
            throw new \InvalidArgumentException(sprintf('--%s must be a whole number of at least %d.', $option, $min));
        }

        return (int) $value;
    }

    /**
     * Relative to the certificate's lifetime, like the default renewal rule: renewal is due
     * in the last third (30 days of a 90-day certificate), urgent in the last tenth.
     *
     * @return array{0: string, 1: string, 2: string} [icon, status, console style]
     */
    protected function expiryStatus(StoredCertificate $cert): array
    {
        $lifetime  = max(1, $cert->expiresAt->getTimestamp() - $cert->issuedAt->getTimestamp());
        $remaining = $cert->expiresAt->getTimestamp() - time();

        return match (true) {
            $remaining <= 0              => ['✗', 'Expired', 'fg=red'],
            $remaining <= $lifetime / 10 => ['!', 'Expiring soon', 'fg=red'],
            $remaining <= $lifetime / 3  => ['!', 'Renewal due', 'fg=yellow'],
            default                      => ['✓', 'Valid', 'fg=green'],
        };
    }
}
