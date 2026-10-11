<?php

declare(strict_types=1);

namespace CoyoteCert\Console;

use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Provider\GoogleTrustServices;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;
use CoyoteCert\Provider\SslCom;
use CoyoteCert\Provider\ZeroSSL;

class ProviderResolver
{
    /**
     * EAB credentials are only needed to register an account; pass $requireEab = false when
     * the stored account is used as is (e.g. to revoke).
     *
     * @throws \InvalidArgumentException for unknown provider names or missing required credentials.
     */
    public static function resolve(
        string  $name,
        ?string $zeroSslKey = null,
        ?string $eabKid = null,
        ?string $eabHmac = null,
        bool    $requireEab = true,
    ): AcmeProviderInterface {
        return match (strtolower($name)) {
            'letsencrypt', 'le'
                => new LetsEncrypt(),

            'letsencrypt-staging', 'le-staging', 'staging'
                => new LetsEncryptStaging(),

            'zerossl'
                => new ZeroSSL(apiKey: $zeroSslKey, eabKid: $eabKid, eabHmac: $eabHmac),

            'google', 'google-trust-services', 'gts' => self::requireEab(
                fn(string $kid, string $hmac) => new GoogleTrustServices($kid, $hmac),
                $eabKid,
                $eabHmac,
                'Google Trust Services',
                $requireEab,
            ),

            'sslcom', 'ssl.com'
                => new SslCom($eabKid, $eabHmac),

            default => throw new \InvalidArgumentException(
                sprintf(
                    'Unknown provider "%s". Supported: letsencrypt, letsencrypt-staging, zerossl, google, sslcom.',
                    $name,
                ),
            ),
        };
    }

    private static function requireEab(
        callable $factory,
        ?string $kid,
        ?string $hmac,
        string $providerName,
        bool $required,
    ): AcmeProviderInterface {
        if ($required && ($kid === null || $hmac === null)) {
            throw new \InvalidArgumentException(
                sprintf('%s requires --eab-kid and --eab-hmac (or ACME_EAB_KID and ACME_EAB_HMAC).', $providerName),
            );
        }

        return $factory($kid ?? '', $hmac ?? '');
    }
}
