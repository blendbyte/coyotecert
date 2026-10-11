<?php

namespace CoyoteCert\Console;

use Composer\InstalledVersions;
use CoyoteCert\Console\Command\IssueCommand;
use CoyoteCert\Console\Command\ListCommand;
use CoyoteCert\Console\Command\RevokeCommand;
use CoyoteCert\Console\Command\StatusCommand;
use Symfony\Component\Console\Application as BaseApplication;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Application extends BaseApplication
{
    private const REPO = 'https://github.com/blendbyte/coyotecert';

    public function __construct()
    {
        $version = InstalledVersions::getPrettyVersion('blendbyte/coyotecert') ?? 'dev';
        parent::__construct('coyote', $version);

        $this->addCommands([
            new IssueCommand(),
            new StatusCommand(),
            new ListCommand(),
            new RevokeCommand(),
        ]);
    }

    public function doRun(InputInterface $input, OutputInterface $output): int
    {
        // coyote --help with no command → show app list (which includes getHelp()),
        // not the "list" command's own man page.
        if ($input->hasParameterOption(['--help', '-h'], true) && !$input->getFirstArgument()) {
            return parent::doRun(new ArrayInput([]), $output);
        }

        return parent::doRun($input, $output);
    }

    public function getLongVersion(): string
    {
        return sprintf(
            '<info>coyote</info> <comment>%s</comment> — ACME v2 TLS certificate manager' . PHP_EOL
            . '  <href=%s>%s</>',
            $this->getVersion(),
            self::REPO,
            self::REPO,
        );
    }

    public function getHelp(): string
    {
        return sprintf(
            '<info>coyote</info> — ACME v2 TLS certificate manager' . PHP_EOL
            . '  Issue, renew, and inspect certificates from <comment>Let\'s Encrypt</comment>, <comment>ZeroSSL</comment>,' . PHP_EOL
            . '  <comment>Google Trust Services</comment>, and <comment>SSL.com</comment>.' . PHP_EOL
            . PHP_EOL
            . '  <href=%1$s>%1$s</>',
            self::REPO,
        );
    }
}
