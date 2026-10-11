<?php

declare(strict_types=1);

use CoyoteCert\Support\Base64;
use CoyoteCert\Support\DnsDigest;

it('make returns a non-empty base64url string', function () {
    $result = DnsDigest::make('token123', 'thumbprint456');

    expect($result)->toBeString()->not->toBeEmpty();
    expect($result)->not->toContain('+');
    expect($result)->not->toContain('/');
    expect($result)->not->toContain('=');
});

it('make produces the correct digest', function () {
    $token      = 'abc123';
    $thumbprint = 'tp-xyz';

    $hash     = hash('sha256', "$token.$thumbprint", true);
    $expected = Base64::urlSafeEncode($hash);

    expect(DnsDigest::make($token, $thumbprint))->toBe($expected);
});

it('createHash returns raw binary bytes', function () {
    $hash = DnsDigest::createHash('t', 'tp');
    expect(strlen($hash))->toBe(32);
});

it('same inputs always produce the same digest', function () {
    $a = DnsDigest::make('tok', 'thumb');
    $b = DnsDigest::make('tok', 'thumb');
    expect($a)->toBe($b);
});

it('different tokens produce different digests', function () {
    $a = DnsDigest::make('token-a', 'thumb');
    $b = DnsDigest::make('token-b', 'thumb');
    expect($a)->not->toBe($b);
});
