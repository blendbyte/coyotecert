<?php

use CoyoteCert\DTO\CertificateBundleData;
use CoyoteCert\Http\Response;

$certA = "-----BEGIN CERTIFICATE-----\nMIIBcert1\n-----END CERTIFICATE-----";
$certB = "-----BEGIN CERTIFICATE-----\nMIIBcert2\n-----END CERTIFICATE-----";
$certC = "-----BEGIN CERTIFICATE-----\nMIIBcert3\n-----END CERTIFICATE-----";

it('parses a single certificate', function () use ($certA) {
    $r      = new Response([], '', 200, $certA);
    $bundle = CertificateBundleData::fromResponse($r);

    expect($bundle->certificate)->toBe($certA);
    expect($bundle->fullchain)->toBe('');
    expect($bundle->caBundle)->toBe('');
});

it('parses a chain with multiple certificates', function () use ($certA, $certB, $certC) {
    $body   = "$certA\n$certB\n$certC";
    $r      = new Response([], '', 200, $body);
    $bundle = CertificateBundleData::fromResponse($r);

    expect($bundle->certificate)->toBe($certA);
    expect($bundle->fullchain)->toContain($certA);
    expect($bundle->fullchain)->toContain($certB);
    expect($bundle->caBundle)->toContain($certB);
    expect($bundle->caBundle)->toContain($certC);
    expect($bundle->caBundle)->not->toContain($certA);
});

it('returns empty strings when no certificate is found', function () {
    $r      = new Response([], '', 200, 'no cert here');
    $bundle = CertificateBundleData::fromResponse($r);

    expect($bundle->certificate)->toBe('');
    expect($bundle->fullchain)->toBe('');
    expect($bundle->caBundle)->toBe('');
});

it('is readonly — properties cannot be changed', function () use ($certA) {
    $r      = new Response([], '', 200, $certA);
    $bundle = CertificateBundleData::fromResponse($r);

    expect(fn() => $bundle->certificate = 'modified')->toThrow(\Error::class);
});
