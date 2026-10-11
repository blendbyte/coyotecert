<?php

namespace CoyoteCert\Console\Command;

use CoyoteCert\Console\ProviderResolver;
use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\KeyType;
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

use function Termwind\render;

#[AsCommand(name: 'revoke', description: 'Revoke a stored certificate')]
class RevokeCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('identifier', 'i', InputOption::VALUE_REQUIRED, 'Primary identifier of the certificate to revoke')
            ->addOption('provider', 'p', InputOption::VALUE_REQUIRED, 'CA the certificate was issued by: letsencrypt, letsencrypt-staging, zerossl, google, sslcom')
            ->addOption('storage', 's', InputOption::VALUE_REQUIRED, 'Directory where certificates are stored', './certs')
            ->addOption('key-type', null, InputOption::VALUE_REQUIRED, 'Key type of the certificate: ec256, ec384, rsa2048, rsa4096', 'ec256')
            ->addOption('reason', null, InputOption::VALUE_REQUIRED, 'Revocation reason: unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessationofoperation, certificatehold, privilegewithdrawn, aacompromise', 'unspecified')
            ->addOption('zerossl-key', null, InputOption::VALUE_REQUIRED, 'ZeroSSL API key for EAB provisioning')
            ->addOption('eab-kid', null, InputOption::VALUE_REQUIRED, 'EAB key ID (Google Trust Services, SSL.com, or ZeroSSL pre-provisioned)')
            ->addOption('eab-hmac', null, InputOption::VALUE_REQUIRED, 'EAB HMAC key');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $identifier = $input->getOption('identifier');
        $provider   = $input->getOption('provider');

        if ($identifier === null) {
            $this->renderError('--identifier is required.');

            return Command::FAILURE;
        }

        if ($provider === null) {
            $this->renderError('--provider is required. It must match the CA that issued the certificate.');

            return Command::FAILURE;
        }

        try {
            $acmeProvider = ProviderResolver::resolve(
                $provider,
                zeroSslKey: $input->getOption('zerossl-key'),
                eabKid: $input->getOption('eab-kid'),
                eabHmac: $input->getOption('eab-hmac'),
            );
        } catch (\InvalidArgumentException $e) {
            $this->renderError($e->getMessage());

            return Command::FAILURE;
        }

        try {
            $keyType = $this->resolveKeyType($input->getOption('key-type'));
        } catch (\InvalidArgumentException $e) {
            $this->renderError($e->getMessage());

            return Command::FAILURE;
        }

        try {
            $reason = $this->resolveReason($input->getOption('reason'));
        } catch (\InvalidArgumentException $e) {
            $this->renderError($e->getMessage());

            return Command::FAILURE;
        }

        $storagePath = $input->getOption('storage');
        $fs          = new FilesystemStorage($storagePath);
        $cert        = $fs->getCertificate($identifier, $keyType);

        if ($cert === null) {
            $this->renderError(sprintf(
                'No certificate found for %s in %s.',
                $identifier,
                $storagePath,
            ));

            return Command::FAILURE;
        }

        $coyote = CoyoteCert::with($acmeProvider)
            ->storage($fs);

        try {
            $this->performRevoke($coyote, $cert, $reason);
        } catch (AuthException $e) {
            $this->renderError('Authentication failed.', htmlspecialchars($e->getMessage()));

            return Command::FAILURE;
        } catch (AcmeException $e) {
            $this->renderError('Revocation failed.', htmlspecialchars($e->getMessage()));

            return Command::FAILURE;
        }

        render(sprintf(
            <<<HTML
                <div class="mt-1 mb-1">
                    <div class="ml-2">
                        <span class="text-green-500 font-bold">✓</span>
                        <span class="ml-1 font-bold">Certificate revoked</span>
                    </div>
                    <table class="mt-1 ml-4">
                        <tr>
                            <td class="text-gray-500 pr-4">Identifier(s)</td>
                            <td>%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Reason</td>
                            <td>%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Provider</td>
                            <td>%s</td>
                        </tr>
                        <tr>
                            <td class="text-gray-500 pr-4">Storage</td>
                            <td>%s</td>
                        </tr>
                    </table>
                </div>
                HTML,
            implode(', ', $cert->domains),
            $reason->name,
            $acmeProvider->getDisplayName(),
            $storagePath,
        ));

        return Command::SUCCESS;
    }

    protected function performRevoke(CoyoteCert $coyote, StoredCertificate $cert, RevocationReason $reason): void
    {
        $coyote->revoke($cert, $reason);
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

    private function resolveReason(string $reason): RevocationReason
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
                sprintf(
                    'Unknown reason "%s". Supported: unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessationofoperation, certificatehold, privilegewithdrawn, aacompromise.',
                    $reason,
                ),
            ),
        };
    }

    private function renderError(string $message, string $detail = ''): void
    {
        $detailHtml = $detail !== ''
            ? sprintf('<div class="ml-4 mt-1 text-red-400">%s</div>', $detail)
            : '';

        render(sprintf(
            <<<HTML
                <div class="mt-1 mb-1">
                    <div class="ml-2">
                        <span class="text-red-500 font-bold">✗</span>
                        <span class="ml-1 text-red-500">%s</span>
                    </div>
                    %s
                </div>
                HTML,
            $message,
            $detailHtml,
        ));
    }
}
