<?php

use CoyoteCert\DTO\EabCredentials;

it('stores kid and hmacKey', function () {
    $creds = new EabCredentials('my-kid', 'my-hmac');

    expect($creds->kid)->toBe('my-kid');
    expect($creds->hmacKey)->toBe('my-hmac');
});

it('is readonly — properties cannot be changed', function () {
    $creds = new EabCredentials('kid', 'hmac');

    expect(fn() => $creds->kid = 'other')
        ->toThrow(\Error::class);
});
