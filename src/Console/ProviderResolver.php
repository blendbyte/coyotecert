<?php

namespace CoyoteCert\Console;

use CoyoteCert\Provider\AcmeProviderInterface;
use CoyoteCert\Provider\BuypassGo;
use CoyoteCert\Provider\BuypassGoStaging;
use CoyoteCert\Provider\GoogleTrustServices;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;
use CoyoteCert\Provider\SslCom;
use CoyoteCert\Provider\ZeroSSL;

class ProviderResolver
{
    /**
     * @throws \InvalidArgumentException for unknown provider names or missing required credentials.
     */
    public static function resolve(
        string  $name,
        ?string $zeroSslKey = null,
        ?string $eabKid = null,
        ?string $eabHmac = null,
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
            ),

            'sslcom', 'ssl.com' => self::requireEab(
                fn(string $kid, string $hmac) => new SslCom($kid, $hmac),
                $eabKid,
                $eabHmac,
                'SSL.com',
            ),

            'buypass'
                => new BuypassGo(),

            'buypass-staging'
                => new BuypassGoStaging(),

            default => throw new \InvalidArgumentException(
                sprintf(
                    'Unknown provider "%s". Supported: letsencrypt, letsencrypt-staging, zerossl, google, buypass, buypass-staging, sslcom.',
                    $name,
                ),
            ),
        };
    }

    private static function requireEab(callable $factory, ?string $kid, ?string $hmac, string $providerName): AcmeProviderInterface
    {
        if ($kid === null || $hmac === null) {
            throw new \InvalidArgumentException(
                sprintf('%s requires --eab-kid and --eab-hmac.', $providerName),
            );
        }

        return $factory($kid, $hmac);
    }
}
