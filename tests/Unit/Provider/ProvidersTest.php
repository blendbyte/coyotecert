<?php

use CoyoteCert\Provider\BuypassGo;
use CoyoteCert\Provider\BuypassGoStaging;
use CoyoteCert\Provider\CustomProvider;
use CoyoteCert\Provider\GoogleTrustServices;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;
use CoyoteCert\Provider\SslCom;
use CoyoteCert\Provider\ZeroSSL;

// ── LetsEncrypt ───────────────────────────────────────────────────────────────

it('LetsEncrypt has correct directory URL', function () {
    $p = new LetsEncrypt();
    expect($p->getDirectoryUrl())->toContain('acme-v02.api.letsencrypt.org');
});

it('LetsEncrypt does not require EAB', function () {
    expect((new LetsEncrypt())->isEabRequired())->toBeFalse();
    expect((new LetsEncrypt())->getEabCredentials('any@example.com'))->toBeNull();
});

it('LetsEncrypt supports profiles', function () {
    expect((new LetsEncrypt())->supportsProfiles())->toBeTrue();
});

it('LetsEncrypt verifies TLS', function () {
    expect((new LetsEncrypt())->verifyTls())->toBeTrue();
});

it('LetsEncrypt has a display name', function () {
    expect((new LetsEncrypt())->getDisplayName())->toContain("Let's Encrypt");
});

// ── LetsEncryptStaging ────────────────────────────────────────────────────────

it('LetsEncryptStaging has a different directory URL from production', function () {
    expect((new LetsEncryptStaging())->getDirectoryUrl())
        ->not->toBe((new LetsEncrypt())->getDirectoryUrl());
});

it('LetsEncryptStaging does not require EAB', function () {
    expect((new LetsEncryptStaging())->isEabRequired())->toBeFalse();
    expect((new LetsEncryptStaging())->getEabCredentials('e@example.com'))->toBeNull();
});

it('LetsEncryptStaging has a display name', function () {
    expect((new LetsEncryptStaging())->getDisplayName())->toContain("Let's Encrypt");
});

it('LetsEncryptStaging supports profiles', function () {
    expect((new LetsEncryptStaging())->supportsProfiles())->toBeTrue();
});

it('LetsEncryptStaging verifies TLS', function () {
    expect((new LetsEncryptStaging())->verifyTls())->toBeTrue();
});

// ── BuypassGo ────────────────────────────────────────────────────────────────

it('BuypassGo has correct directory URL', function () {
    expect((new BuypassGo())->getDirectoryUrl())->toContain('buypass');
});

it('BuypassGo does not require EAB', function () {
    expect((new BuypassGo())->isEabRequired())->toBeFalse();
    expect((new BuypassGo())->getEabCredentials('e@example.com'))->toBeNull();
});

it('BuypassGo has a display name', function () {
    expect((new BuypassGo())->getDisplayName())->toContain('Buypass');
});

it('BuypassGo does not support profiles', function () {
    expect((new BuypassGo())->supportsProfiles())->toBeFalse();
});

it('BuypassGo verifies TLS', function () {
    expect((new BuypassGo())->verifyTls())->toBeTrue();
});

it('BuypassGoStaging has a different directory URL', function () {
    expect((new BuypassGoStaging())->getDirectoryUrl())
        ->not->toBe((new BuypassGo())->getDirectoryUrl());
});

it('BuypassGoStaging has a display name', function () {
    expect((new BuypassGoStaging())->getDisplayName())->toContain('Buypass');
});

it('BuypassGoStaging does not require EAB', function () {
    expect((new BuypassGoStaging())->isEabRequired())->toBeFalse();
    expect((new BuypassGoStaging())->getEabCredentials('e@example.com'))->toBeNull();
});

it('BuypassGoStaging does not support profiles', function () {
    expect((new BuypassGoStaging())->supportsProfiles())->toBeFalse();
});

it('BuypassGoStaging verifies TLS', function () {
    expect((new BuypassGoStaging())->verifyTls())->toBeTrue();
});

// ── ZeroSSL ───────────────────────────────────────────────────────────────────

it('ZeroSSL requires EAB', function () {
    expect((new ZeroSSL())->isEabRequired())->toBeTrue();
});

it('ZeroSSL returns pre-provisioned EAB credentials', function () {
    $p    = new ZeroSSL(eabKid: 'kid1', eabHmac: 'hmac1');
    $creds = $p->getEabCredentials('test@example.com');

    expect($creds)->not->toBeNull();
    expect($creds->kid)->toBe('kid1');
    expect($creds->hmacKey)->toBe('hmac1');
});

it('ZeroSSL returns null when no credentials configured', function () {
    expect((new ZeroSSL())->getEabCredentials('test@example.com'))->toBeNull();
});

it('ZeroSSL does not support profiles', function () {
    expect((new ZeroSSL())->supportsProfiles())->toBeFalse();
});

it('ZeroSSL has a directory URL', function () {
    expect((new ZeroSSL())->getDirectoryUrl())->toContain('zerossl.com');
});

it('ZeroSSL has a display name', function () {
    expect((new ZeroSSL())->getDisplayName())->toBe('ZeroSSL');
});

it('ZeroSSL verifies TLS', function () {
    expect((new ZeroSSL())->verifyTls())->toBeTrue();
});

// ── GoogleTrustServices ───────────────────────────────────────────────────────

it('GoogleTrustServices returns EAB credentials', function () {
    $p     = new GoogleTrustServices(eabKid: 'gkid', eabHmac: 'ghmac');
    $creds = $p->getEabCredentials('test@example.com');

    expect($creds->kid)->toBe('gkid');
    expect($creds->hmacKey)->toBe('ghmac');
});

it('GoogleTrustServices requires EAB', function () {
    expect((new GoogleTrustServices(eabKid: 'k', eabHmac: 'h'))->isEabRequired())->toBeTrue();
});

it('GoogleTrustServices has a directory URL', function () {
    expect((new GoogleTrustServices(eabKid: 'k', eabHmac: 'h'))->getDirectoryUrl())->toContain('pki.goog');
});

it('GoogleTrustServices has a display name', function () {
    expect((new GoogleTrustServices(eabKid: 'k', eabHmac: 'h'))->getDisplayName())->toContain('Google');
});

it('GoogleTrustServices does not support profiles', function () {
    expect((new GoogleTrustServices(eabKid: 'k', eabHmac: 'h'))->supportsProfiles())->toBeFalse();
});

it('GoogleTrustServices verifies TLS', function () {
    expect((new GoogleTrustServices(eabKid: 'k', eabHmac: 'h'))->verifyTls())->toBeTrue();
});

// ── SslCom ────────────────────────────────────────────────────────────────────

it('SslCom returns EAB credentials', function () {
    $p     = new SslCom(eabKid: 'skid', eabHmac: 'shmac');
    $creds = $p->getEabCredentials('test@example.com');

    expect($creds->kid)->toBe('skid');
    expect($creds->hmacKey)->toBe('shmac');
});

it('SslCom RSA and ECC variants have different directory URLs', function () {
    $rsa = new SslCom(eabKid: 'k', eabHmac: 'h');
    $ecc = new SslCom(eabKid: 'k', eabHmac: 'h', ecc: true);

    expect($rsa->getDirectoryUrl())->not->toBe($ecc->getDirectoryUrl());
});

it('SslCom RSA display name contains RSA', function () {
    expect((new SslCom(eabKid: 'k', eabHmac: 'h'))->getDisplayName())->toContain('RSA');
});

it('SslCom ECC display name contains ECC', function () {
    expect((new SslCom(eabKid: 'k', eabHmac: 'h', ecc: true))->getDisplayName())->toContain('ECC');
});

it('SslCom requires EAB', function () {
    expect((new SslCom(eabKid: 'k', eabHmac: 'h'))->isEabRequired())->toBeTrue();
});

it('SslCom does not support profiles', function () {
    expect((new SslCom(eabKid: 'k', eabHmac: 'h'))->supportsProfiles())->toBeFalse();
});

it('SslCom verifies TLS', function () {
    expect((new SslCom(eabKid: 'k', eabHmac: 'h'))->verifyTls())->toBeTrue();
});

// ── CustomProvider ────────────────────────────────────────────────────────────

it('CustomProvider uses the provided directory URL and display name', function () {
    $p = new CustomProvider(
        directoryUrl: 'https://acme.mycorp.com/directory',
        displayName:  'MyCorp CA',
    );

    expect($p->getDirectoryUrl())->toBe('https://acme.mycorp.com/directory');
    expect($p->getDisplayName())->toBe('MyCorp CA');
});

it('CustomProvider with EAB credentials is EAB required', function () {
    $p = new CustomProvider(
        directoryUrl: 'https://acme.mycorp.com/dir',
        eabKid:       'kid',
        eabHmac:      'hmac',
    );

    expect($p->isEabRequired())->toBeTrue();

    $creds = $p->getEabCredentials('a@b.com');
    expect($creds->kid)->toBe('kid');
    expect($creds->hmacKey)->toBe('hmac');
});

it('CustomProvider without EAB credentials is not EAB required', function () {
    $p = new CustomProvider(directoryUrl: 'https://acme.mycorp.com/dir');

    expect($p->isEabRequired())->toBeFalse();
    expect($p->getEabCredentials('a@b.com'))->toBeNull();
});

it('CustomProvider verifyTls defaults to true', function () {
    expect((new CustomProvider(directoryUrl: 'https://host/dir'))->verifyTls())->toBeTrue();
});

it('CustomProvider verifyTls can be disabled', function () {
    $p = new CustomProvider(directoryUrl: 'https://host/dir', verifyTls: false);
    expect($p->verifyTls())->toBeFalse();
});

it('CustomProvider supports profiles when configured', function () {
    $p = new CustomProvider(directoryUrl: 'https://host/dir', profilesSupported: true);
    expect($p->supportsProfiles())->toBeTrue();
});

it('CustomProvider profiles disabled by default', function () {
    expect((new CustomProvider(directoryUrl: 'https://host/dir'))->supportsProfiles())->toBeFalse();
});

// ── Pebble ────────────────────────────────────────────────────────────────────

it('Pebble has the correct default directory URL', function () {
    $p = new \CoyoteCert\Provider\Pebble();
    expect($p->getDirectoryUrl())->toBe('https://localhost:14000/dir');
});

it('Pebble accepts a custom directory URL', function () {
    $p = new \CoyoteCert\Provider\Pebble('https://pebble.local:14000/dir');
    expect($p->getDirectoryUrl())->toBe('https://pebble.local:14000/dir');
});

it('Pebble display name identifies it as a test CA', function () {
    expect((new \CoyoteCert\Provider\Pebble())->getDisplayName())->toContain('Pebble');
});

it('Pebble does not require EAB by default', function () {
    expect((new \CoyoteCert\Provider\Pebble())->isEabRequired())->toBeFalse();
});

it('Pebble requires EAB when configured', function () {
    $p = new \CoyoteCert\Provider\Pebble(eab: true);
    expect($p->isEabRequired())->toBeTrue();
});

it('Pebble returns null EAB credentials when not configured', function () {
    expect((new \CoyoteCert\Provider\Pebble())->getEabCredentials('test@example.com'))->toBeNull();
});

it('Pebble returns EAB credentials when configured', function () {
    $p     = new \CoyoteCert\Provider\Pebble(eabKid: 'kid1', eabHmac: 'hmac1');
    $creds = $p->getEabCredentials('test@example.com');

    expect($creds->kid)->toBe('kid1');
    expect($creds->hmacKey)->toBe('hmac1');
});

it('Pebble skips TLS verification by default', function () {
    expect((new \CoyoteCert\Provider\Pebble())->verifyTls())->toBeFalse();
});

it('Pebble supports profiles', function () {
    expect((new \CoyoteCert\Provider\Pebble())->supportsProfiles())->toBeTrue();
});
