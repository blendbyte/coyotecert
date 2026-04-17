<?php

use CoyoteCert\Support\Base64;
use CoyoteCert\Support\JsonWebKey;

it('throws when given an invalid private key string', function () {
    expect(fn() => JsonWebKey::compute('not-a-pem'))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Can not create private key');
});

it('computes an RSA JWK with e, kty, n', function () {
    $jwk = JsonWebKey::compute(rsaKeyPem());

    expect($jwk)->toHaveKeys(['e', 'kty', 'n']);
    expect($jwk['kty'])->toBe('RSA');
    expect($jwk['e'])->toBeString()->not->toBeEmpty();
    expect($jwk['n'])->toBeString()->not->toBeEmpty();
});

it('RSA JWK keys are in lexicographic order for correct thumbprint', function () {
    $jwk = JsonWebKey::compute(rsaKeyPem());

    expect(array_keys($jwk))->toBe(['e', 'kty', 'n']);
});

it('computes an EC P-256 JWK with crv, kty, x, y', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('prime256v1'));

    expect($jwk)->toHaveKeys(['crv', 'kty', 'x', 'y']);
    expect($jwk['kty'])->toBe('EC');
    expect($jwk['crv'])->toBe('P-256');
    expect($jwk['x'])->toBeString()->not->toBeEmpty();
    expect($jwk['y'])->toBeString()->not->toBeEmpty();
});

it('EC P-256 coordinates are padded to 32 bytes', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('prime256v1'));

    expect(strlen(Base64::urlSafeDecode($jwk['x'])))->toBe(32);
    expect(strlen(Base64::urlSafeDecode($jwk['y'])))->toBe(32);
});

it('computes an EC P-384 JWK with crv P-384', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('secp384r1'));

    expect($jwk['crv'])->toBe('P-384');
    expect(strlen(Base64::urlSafeDecode($jwk['x'])))->toBe(48);
    expect(strlen(Base64::urlSafeDecode($jwk['y'])))->toBe(48);
});

it('EC JWK keys are in lexicographic order for correct thumbprint', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('prime256v1'));

    expect(array_keys($jwk))->toBe(['crv', 'kty', 'x', 'y']);
});

it('thumbprint returns a non-empty base64url string', function () {
    $jwk        = JsonWebKey::compute(rsaKeyPem());
    $thumbprint = JsonWebKey::thumbprint($jwk);

    expect($thumbprint)->toBeString()->not->toBeEmpty();
    expect($thumbprint)->not->toContain('=');
    expect($thumbprint)->not->toContain('+');
    expect($thumbprint)->not->toContain('/');
});

it('throws for an unsupported EC curve', function () {
    expect(fn() => JsonWebKey::compute(ecKeyPem('secp521r1')))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class);
});
