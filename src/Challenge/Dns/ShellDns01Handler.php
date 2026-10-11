<?php

declare(strict_types=1);

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
 * Don't quote the placeholders in the template; the values are already escaped.
 * Each cleanup() call runs the cleanup command for one deployed value, in deploy
 * order and with the same placeholders, so a hook can remove exactly the value it
 * added (a wildcard and its base name share one _acme-challenge name). A non-zero exit code, or running longer than $timeout
 * seconds, throws ChallengeException.
 *
 * Usage:
 *
 *   new ShellDns01Handler('/usr/local/bin/dns-hook {domain} {keyauth}')
 *   new ShellDns01Handler(
 *       deployCommand:  '/usr/local/bin/dns-hook add {domain} {keyauth}',
 *       cleanupCommand: '/usr/local/bin/dns-hook del {domain} {keyauth}',
 *   )
 */
class ShellDns01Handler extends AbstractDns01Handler
{
    /** @var array<string, list<string>> domain => deployed TXT values */
    private array $values = [];

    public function __construct(
        private readonly string $deployCommand,
        private readonly ?string $cleanupCommand = null,
        private readonly int $timeout = 120,
    ) {}

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->maybePurgeExisting($domain);
        $this->run($this->deployCommand, $domain, $keyAuthorization);
        $this->values[$domain][] = $keyAuthorization;
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        if ($this->cleanupCommand === null) {
            return;
        }

        // Nothing tracked (e.g. a fresh instance cleaning up): run without a value
        $values = $this->values[$domain] ?? [];
        $value  = array_shift($values)   ?? '';

        if ($values === []) {
            unset($this->values[$domain]);
        } else {
            $this->values[$domain] = $values;
        }

        $this->run($this->cleanupCommand, $domain, $value);
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

        // Drain stdout and stderr together: reading one to the end first deadlocks once the
        // command fills the other pipe's buffer
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stderr   = '';
        $deadline = time() + $this->timeout;

        while (!feof($pipes[1]) || !feof($pipes[2])) {
            if (time() >= $deadline) {
                proc_terminate($proc);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($proc);

                throw new ChallengeException(
                    sprintf('ShellDns01Handler: "%s" did not finish within %d seconds.', $cmdTemplate, $this->timeout),
                );
            }

            $read   = array_filter([$pipes[1], $pipes[2]], static fn($pipe): bool => !feof($pipe));
            $write  = null;
            $except = null;

            if (stream_select($read, $write, $except, 1) === false) {
                break;
            }

            foreach ($read as $pipe) {
                $chunk = (string) fread($pipe, 8192);

                if ($pipe === $pipes[2]) {
                    $stderr .= $chunk;
                }
            }
        }

        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($proc);
        $stderr   = trim($stderr);

        if ($exitCode !== 0) {
            $detail = $stderr !== '' ? ': ' . (strlen($stderr) > 1000 ? substr($stderr, 0, 1000) . '...' : $stderr) : '.';

            throw new ChallengeException(
                sprintf('ShellDns01Handler: "%s" exited with code %d%s', $cmdTemplate, $exitCode, $detail),
            );
        }
    }
}
