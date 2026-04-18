<?php

namespace CoyoteCert\Console;

use CoyoteCert\Challenge\Dns\AbstractDns01Handler;
use CoyoteCert\Challenge\Dns\CloudflareDns01Handler;
use CoyoteCert\Challenge\Dns\ClouDnsDns01Handler;
use CoyoteCert\Challenge\Dns\DigitalOceanDns01Handler;
use CoyoteCert\Challenge\Dns\HetznerDns01Handler;
use CoyoteCert\Challenge\Dns\Route53Dns01Handler;
use CoyoteCert\Challenge\Dns\ShellDns01Handler;

/**
 * Instantiates a DNS-01 challenge handler from a provider name.
 *
 * Credentials are read from environment variables so that secrets never
 * appear on the command line. Required variables are listed per provider:
 *
 *   cloudflare   CLOUDFLARE_API_TOKEN           optional: CLOUDFLARE_ZONE_ID
 *   hetzner      HETZNER_API_TOKEN              optional: HETZNER_ZONE_ID
 *   digitalocean DO_API_TOKEN                   optional: DO_ZONE
 *   cloudns      CLOUDNS_AUTH_ID                          CLOUDNS_AUTH_PASSWORD
 *                                               optional: CLOUDNS_ZONE
 *   route53      AWS_ACCESS_KEY_ID                        AWS_SECRET_ACCESS_KEY
 *                                               optional: AWS_ROUTE53_ZONE_ID
 *   exec         DNS_DEPLOY_CMD                 optional: DNS_CLEANUP_CMD
 */
class DnsHandlerResolver
{
    /**
     * @throws \InvalidArgumentException for unknown provider names or missing required env vars.
     */
    public static function resolve(string $provider): AbstractDns01Handler
    {
        return match (strtolower($provider)) {
            'cloudflare'
                => new CloudflareDns01Handler(
                    self::env('CLOUDFLARE_API_TOKEN', 'cloudflare'),
                    self::optionalEnv('CLOUDFLARE_ZONE_ID'),
                ),

            'hetzner'
                => new HetznerDns01Handler(
                    self::env('HETZNER_API_TOKEN', 'hetzner'),
                    self::optionalEnv('HETZNER_ZONE_ID'),
                ),

            'digitalocean', 'do'
                => new DigitalOceanDns01Handler(
                    self::env('DO_API_TOKEN', 'digitalocean'),
                    self::optionalEnv('DO_ZONE'),
                ),

            'cloudns'
                => new ClouDnsDns01Handler(
                    self::env('CLOUDNS_AUTH_ID', 'cloudns'),
                    self::env('CLOUDNS_AUTH_PASSWORD', 'cloudns'),
                    self::optionalEnv('CLOUDNS_ZONE'),
                ),

            'route53'
                => new Route53Dns01Handler(
                    self::env('AWS_ACCESS_KEY_ID', 'route53'),
                    self::env('AWS_SECRET_ACCESS_KEY', 'route53'),
                    self::optionalEnv('AWS_ROUTE53_ZONE_ID'),
                ),

            'exec', 'shell'
                => new ShellDns01Handler(
                    self::env('DNS_DEPLOY_CMD', 'exec'),
                    self::optionalEnv('DNS_CLEANUP_CMD'),
                ),

            default => throw new \InvalidArgumentException(
                sprintf(
                    'Unknown DNS provider "%s". Supported: cloudflare, hetzner, digitalocean, cloudns, route53, exec.',
                    $provider,
                ),
            ),
        };
    }

    private static function env(string $var, string $provider): string
    {
        $value = getenv($var);

        if ($value === false || $value === '') {
            throw new \InvalidArgumentException(
                sprintf('DNS provider "%s" requires the %s environment variable.', $provider, $var),
            );
        }

        return $value;
    }

    private static function optionalEnv(string $var): ?string
    {
        $value = getenv($var);

        return ($value !== false && $value !== '') ? $value : null;
    }
}
