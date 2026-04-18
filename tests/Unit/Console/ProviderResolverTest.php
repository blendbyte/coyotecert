<?php

use CoyoteCert\Console\ProviderResolver;
use CoyoteCert\Provider\BuypassGo;
use CoyoteCert\Provider\BuypassGoStaging;
use CoyoteCert\Provider\GoogleTrustServices;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;
use CoyoteCert\Provider\SslCom;
use CoyoteCert\Provider\ZeroSSL;

// ── resolve() ─────────────────────────────────────────────────────────────────

it('resolves letsencrypt', function () {
    expect(ProviderResolver::resolve('letsencrypt'))->toBeInstanceOf(LetsEncrypt::class);
});

it('resolves letsencrypt via le alias', function () {
    expect(ProviderResolver::resolve('le'))->toBeInstanceOf(LetsEncrypt::class);
});

it('resolves letsencrypt-staging', function () {
    expect(ProviderResolver::resolve('letsencrypt-staging'))->toBeInstanceOf(LetsEncryptStaging::class);
});

it('resolves letsencrypt-staging via le-staging alias', function () {
    expect(ProviderResolver::resolve('le-staging'))->toBeInstanceOf(LetsEncryptStaging::class);
});

it('resolves letsencrypt-staging via staging alias', function () {
    expect(ProviderResolver::resolve('staging'))->toBeInstanceOf(LetsEncryptStaging::class);
});

it('resolves zerossl', function () {
    expect(ProviderResolver::resolve('zerossl'))->toBeInstanceOf(ZeroSSL::class);
});

it('resolves zerossl with an api key', function () {
    expect(ProviderResolver::resolve('zerossl', zeroSslKey: 'mykey'))->toBeInstanceOf(ZeroSSL::class);
});

it('resolves zerossl with pre-provisioned EAB', function () {
    expect(ProviderResolver::resolve('zerossl', eabKid: 'kid', eabHmac: 'hmac'))->toBeInstanceOf(ZeroSSL::class);
});

it('resolves google', function () {
    expect(ProviderResolver::resolve('google', eabKid: 'k', eabHmac: 'h'))->toBeInstanceOf(GoogleTrustServices::class);
});

it('resolves google via google-trust-services alias', function () {
    expect(ProviderResolver::resolve('google-trust-services', eabKid: 'k', eabHmac: 'h'))->toBeInstanceOf(GoogleTrustServices::class);
});

it('resolves google via gts alias', function () {
    expect(ProviderResolver::resolve('gts', eabKid: 'k', eabHmac: 'h'))->toBeInstanceOf(GoogleTrustServices::class);
});

it('resolves sslcom', function () {
    expect(ProviderResolver::resolve('sslcom', eabKid: 'k', eabHmac: 'h'))->toBeInstanceOf(SslCom::class);
});

it('resolves sslcom via ssl.com alias', function () {
    expect(ProviderResolver::resolve('ssl.com', eabKid: 'k', eabHmac: 'h'))->toBeInstanceOf(SslCom::class);
});

it('resolves buypass', function () {
    expect(ProviderResolver::resolve('buypass'))->toBeInstanceOf(BuypassGo::class);
});

it('resolves buypass-staging', function () {
    expect(ProviderResolver::resolve('buypass-staging'))->toBeInstanceOf(BuypassGoStaging::class);
});

it('is case-insensitive', function () {
    expect(ProviderResolver::resolve('LetsEncrypt'))->toBeInstanceOf(LetsEncrypt::class);
    expect(ProviderResolver::resolve('ZEROSSL'))->toBeInstanceOf(ZeroSSL::class);
});

it('throws for an unknown provider', function () {
    ProviderResolver::resolve('unknownca');
})->throws(\InvalidArgumentException::class);

it('throws for google without eab-kid', function () {
    ProviderResolver::resolve('google', eabHmac: 'hmac');
})->throws(\InvalidArgumentException::class, 'eab-kid');

it('throws for google without eab-hmac', function () {
    ProviderResolver::resolve('google', eabKid: 'kid');
})->throws(\InvalidArgumentException::class, 'eab-hmac');

it('throws for sslcom without EAB credentials', function () {
    ProviderResolver::resolve('sslcom');
})->throws(\InvalidArgumentException::class, 'eab-kid');

// ── getSlug() ─────────────────────────────────────────────────────────────────

it('letsencrypt slug is letsencrypt', function () {
    expect(ProviderResolver::resolve('letsencrypt')->getSlug())->toBe('letsencrypt');
});

it('letsencrypt-staging slug is letsencrypt-staging', function () {
    expect(ProviderResolver::resolve('letsencrypt-staging')->getSlug())->toBe('letsencrypt-staging');
});

it('zerossl slug is zerossl', function () {
    expect(ProviderResolver::resolve('zerossl')->getSlug())->toBe('zerossl');
});

it('google slug is google', function () {
    expect(ProviderResolver::resolve('google', eabKid: 'k', eabHmac: 'h')->getSlug())->toBe('google');
});

it('buypass slug is buypass', function () {
    expect(ProviderResolver::resolve('buypass')->getSlug())->toBe('buypass');
});

it('buypass-staging slug is buypass-staging', function () {
    expect(ProviderResolver::resolve('buypass-staging')->getSlug())->toBe('buypass-staging');
});

it('sslcom slug is sslcom', function () {
    expect(ProviderResolver::resolve('sslcom', eabKid: 'k', eabHmac: 'h')->getSlug())->toBe('sslcom');
});

it('aliases resolve to the same slug as the canonical name', function () {
    expect(ProviderResolver::resolve('le')->getSlug())->toBe(ProviderResolver::resolve('letsencrypt')->getSlug());
    expect(ProviderResolver::resolve('staging')->getSlug())->toBe(ProviderResolver::resolve('letsencrypt-staging')->getSlug());
    expect(ProviderResolver::resolve('gts', eabKid: 'k', eabHmac: 'h')->getSlug())->toBe(ProviderResolver::resolve('google', eabKid: 'k', eabHmac: 'h')->getSlug());
});
