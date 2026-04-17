<?php

use CoyoteCert\Support\JsonWebKey;
use CoyoteCert\Support\Thumbprint;

it('make returns a non-empty base64url string for an RSA key', function () {
    $pem    = rsaKeyPem();
    $result = Thumbprint::make($pem);

    expect($result)->toBeString()->not->toBeEmpty();
    expect($result)->not->toContain('=');
    expect($result)->not->toContain('+');
    expect($result)->not->toContain('/');
});

it('make matches manual thumbprint computation', function () {
    $pem      = rsaKeyPem();
    $jwk      = JsonWebKey::compute($pem);
    $expected = JsonWebKey::thumbprint($jwk);

    expect(Thumbprint::make($pem))->toBe($expected);
});

it('make returns a non-empty base64url string for an EC key', function () {
    $result = Thumbprint::make(ecKeyPem('prime256v1'));
    expect($result)->toBeString()->not->toBeEmpty();
});
