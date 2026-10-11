<?php

declare(strict_types=1);

use CoyoteCert\Console\Application;
use Symfony\Component\Console\Tester\ApplicationTester;

it('registers the issue, status, certs, and revoke commands', function () {
    $app = new Application();

    expect($app->has('issue'))->toBeTrue();
    expect($app->has('status'))->toBeTrue();
    expect($app->has('certs'))->toBeTrue();
    expect($app->has('revoke'))->toBeTrue();
});

it('getLongVersion contains the app name, version, and repo URL', function () {
    $app     = new Application();
    $version = $app->getLongVersion();

    expect($version)->toContain('coyote');
    expect($version)->toMatch('/\d+\.\d+\.\d+|dev/');
    expect($version)->toContain('github.com/blendbyte/coyotecert');
});

it('getHelp describes the app and lists supported CAs', function () {
    $app  = new Application();
    $help = $app->getHelp();

    expect($help)->toContain('coyote');
    expect($help)->toContain("Let's Encrypt");
    expect($help)->toContain('ZeroSSL');
    expect($help)->toContain('SSL.com');
});

it('doRun shows the command list when --help is passed with no command', function () {
    $app = new Application();
    $app->setAutoExit(false);

    $tester = new ApplicationTester($app);
    $tester->run(['--help' => true]);
    $output = $tester->getDisplay();

    expect($output)->toContain('issue');
    expect($output)->toContain('status');
    expect($output)->toContain('certs');
    expect($output)->toContain('revoke');
});

it('doRun delegates --help to the named command when a command is given', function () {
    $app = new Application();
    $app->setAutoExit(false);

    $tester = new ApplicationTester($app);
    $tester->run(['command' => 'issue', '--help' => true]);
    $output = $tester->getDisplay();

    expect($output)->toContain('--identifier');
    expect($output)->toContain('--webroot');
});
