<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Exceptions\ChallengeException;

/**
 * DNS-01 challenge handler that delegates to a shell command.
 *
 * Useful for nsupdate, acme.sh/Certbot hook scripts, or any CLI tool that can
 * set and remove DNS TXT records. Placeholders {domain} and {keyauth} in the
 * command template are replaced with shell-escaped values. The environment
 * variables ACME_DOMAIN and ACME_KEYAUTH are also injected so scripts that
 * prefer the environment do not need explicit argument placeholders.
 *
 * A non-zero exit code throws ChallengeException.
 *
 * Usage:
 *
 *   new ShellDns01Handler('/usr/local/bin/dns-hook {domain} {keyauth}')
 *   new ShellDns01Handler(
 *       deployCommand:  '/usr/local/bin/dns-hook add {domain} {keyauth}',
 *       cleanupCommand: '/usr/local/bin/dns-hook del {domain}',
 *   )
 */
class ShellDns01Handler extends AbstractDns01Handler
{
    public function __construct(
        private readonly string $deployCommand,
        private readonly ?string $cleanupCommand = null,
    ) {}

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->run($this->deployCommand, $domain, $keyAuthorization);
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        if ($this->cleanupCommand === null) {
            return;
        }

        $this->run($this->cleanupCommand, $domain, '');
    }

    /**
     * Execute the command template with {domain} and {keyauth} substituted.
     *
     * Marked protected so tests can subclass and bypass the shell.
     */
    protected function run(string $cmdTemplate, string $domain, string $keyAuth): void
    {
        $command = str_replace(
            ['{domain}', '{keyauth}'],
            [escapeshellarg($domain), escapeshellarg($keyAuth)],
            $cmdTemplate,
        );

        $env = array_merge(
            getenv() ?: [],
            [
                'ACME_DOMAIN'  => $domain,
                'ACME_KEYAUTH' => $keyAuth,
            ],
        );

        $proc = proc_open(
            $command,
            [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
            $pipes,
            null,
            $env,
        );

        if ($proc === false) {
            throw new ChallengeException(
                sprintf('ShellDns01Handler: failed to start "%s".', $cmdTemplate),
            );
        }

        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($proc);

        if ($exitCode !== 0) {
            throw new ChallengeException(
                sprintf('ShellDns01Handler: "%s" exited with code %d.', $cmdTemplate, $exitCode),
            );
        }
    }
}
