<?php

use CoyoteCert\Challenge\Dns\CloudflareDns01Handler;
use CoyoteCert\Challenge\Dns\ClouDnsDns01Handler;
use CoyoteCert\Challenge\Dns\DigitalOceanDns01Handler;
use CoyoteCert\Challenge\Dns\HetznerDns01Handler;
use CoyoteCert\Challenge\Dns\Route53Dns01Handler;
use CoyoteCert\Challenge\Dns\ShellDns01Handler;
use CoyoteCert\Console\DnsHandlerResolver;

afterEach(function () {
    putenv('CLOUDFLARE_API_TOKEN');
    putenv('CLOUDFLARE_ZONE_ID');
    putenv('HETZNER_API_TOKEN');
    putenv('HETZNER_ZONE_ID');
    putenv('DO_API_TOKEN');
    putenv('DO_ZONE');
    putenv('CLOUDNS_AUTH_ID');
    putenv('CLOUDNS_AUTH_PASSWORD');
    putenv('CLOUDNS_ZONE');
    putenv('AWS_ACCESS_KEY_ID');
    putenv('AWS_SECRET_ACCESS_KEY');
    putenv('AWS_ROUTE53_ZONE_ID');
    putenv('DNS_DEPLOY_CMD');
    putenv('DNS_CLEANUP_CMD');
});

// ── cloudflare ────────────────────────────────────────────────────────────────

it('resolves cloudflare', function () {
    putenv('CLOUDFLARE_API_TOKEN=test-token');

    expect(DnsHandlerResolver::resolve('cloudflare'))->toBeInstanceOf(CloudflareDns01Handler::class);
});

it('throws when CLOUDFLARE_API_TOKEN is missing', function () {
    expect(fn() => DnsHandlerResolver::resolve('cloudflare'))
        ->toThrow(\InvalidArgumentException::class, 'CLOUDFLARE_API_TOKEN');
});

// ── hetzner ───────────────────────────────────────────────────────────────────

it('resolves hetzner', function () {
    putenv('HETZNER_API_TOKEN=test-token');

    expect(DnsHandlerResolver::resolve('hetzner'))->toBeInstanceOf(HetznerDns01Handler::class);
});

it('throws when HETZNER_API_TOKEN is missing', function () {
    expect(fn() => DnsHandlerResolver::resolve('hetzner'))
        ->toThrow(\InvalidArgumentException::class, 'HETZNER_API_TOKEN');
});

// ── digitalocean ──────────────────────────────────────────────────────────────

it('resolves digitalocean', function () {
    putenv('DO_API_TOKEN=test-token');

    expect(DnsHandlerResolver::resolve('digitalocean'))->toBeInstanceOf(DigitalOceanDns01Handler::class);
});

it('resolves digitalocean via do alias', function () {
    putenv('DO_API_TOKEN=test-token');

    expect(DnsHandlerResolver::resolve('do'))->toBeInstanceOf(DigitalOceanDns01Handler::class);
});

it('throws when DO_API_TOKEN is missing', function () {
    expect(fn() => DnsHandlerResolver::resolve('digitalocean'))
        ->toThrow(\InvalidArgumentException::class, 'DO_API_TOKEN');
});

// ── cloudns ───────────────────────────────────────────────────────────────────

it('resolves cloudns', function () {
    putenv('CLOUDNS_AUTH_ID=1234');
    putenv('CLOUDNS_AUTH_PASSWORD=secret');

    expect(DnsHandlerResolver::resolve('cloudns'))->toBeInstanceOf(ClouDnsDns01Handler::class);
});

it('throws when CLOUDNS_AUTH_ID is missing', function () {
    putenv('CLOUDNS_AUTH_PASSWORD=secret');

    expect(fn() => DnsHandlerResolver::resolve('cloudns'))
        ->toThrow(\InvalidArgumentException::class, 'CLOUDNS_AUTH_ID');
});

it('throws when CLOUDNS_AUTH_PASSWORD is missing', function () {
    putenv('CLOUDNS_AUTH_ID=1234');

    expect(fn() => DnsHandlerResolver::resolve('cloudns'))
        ->toThrow(\InvalidArgumentException::class, 'CLOUDNS_AUTH_PASSWORD');
});

// ── route53 ───────────────────────────────────────────────────────────────────

it('resolves route53', function () {
    putenv('AWS_ACCESS_KEY_ID=AKIDTEST');
    putenv('AWS_SECRET_ACCESS_KEY=secrettest');

    expect(DnsHandlerResolver::resolve('route53'))->toBeInstanceOf(Route53Dns01Handler::class);
});

it('throws when AWS_ACCESS_KEY_ID is missing', function () {
    putenv('AWS_SECRET_ACCESS_KEY=secrettest');

    expect(fn() => DnsHandlerResolver::resolve('route53'))
        ->toThrow(\InvalidArgumentException::class, 'AWS_ACCESS_KEY_ID');
});

it('throws when AWS_SECRET_ACCESS_KEY is missing', function () {
    putenv('AWS_ACCESS_KEY_ID=AKIDTEST');

    expect(fn() => DnsHandlerResolver::resolve('route53'))
        ->toThrow(\InvalidArgumentException::class, 'AWS_SECRET_ACCESS_KEY');
});

// ── exec / shell ──────────────────────────────────────────────────────────────

it('resolves exec', function () {
    putenv('DNS_DEPLOY_CMD=/hook add {domain} {keyauth}');

    expect(DnsHandlerResolver::resolve('exec'))->toBeInstanceOf(ShellDns01Handler::class);
});

it('resolves exec via shell alias', function () {
    putenv('DNS_DEPLOY_CMD=/hook add {domain} {keyauth}');

    expect(DnsHandlerResolver::resolve('shell'))->toBeInstanceOf(ShellDns01Handler::class);
});

it('throws when DNS_DEPLOY_CMD is missing', function () {
    expect(fn() => DnsHandlerResolver::resolve('exec'))
        ->toThrow(\InvalidArgumentException::class, 'DNS_DEPLOY_CMD');
});

// ── unknown provider ──────────────────────────────────────────────────────────

it('throws for an unknown provider name', function () {
    expect(fn() => DnsHandlerResolver::resolve('godaddy'))
        ->toThrow(\InvalidArgumentException::class, 'Unknown DNS provider "godaddy"');
});
