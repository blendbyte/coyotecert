<?php

use CoyoteCert\Storage\StoredCertificate;

function makeCert(array $overrides = []): StoredCertificate
{
    return new StoredCertificate(
        certificate: $overrides['certificate'] ?? 'cert-pem',
        privateKey:  $overrides['privateKey']  ?? 'key-pem',
        fullchain:   $overrides['fullchain']   ?? 'fullchain-pem',
        caBundle:    $overrides['caBundle']    ?? 'ca-bundle-pem',
        issuedAt:    $overrides['issuedAt']    ?? new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt:   $overrides['expiresAt']   ?? new DateTimeImmutable('2026-04-01T00:00:00+00:00'),
        domains:     $overrides['domains']     ?? ['example.com'],
    );
}

it('roundtrips through toArray/fromArray', function () {
    $cert = makeCert();

    expect(StoredCertificate::fromArray($cert->toArray())->toArray())->toBe($cert->toArray());
});

it('toArray contains all expected keys', function () {
    $data = makeCert()->toArray();

    expect($data)->toHaveKeys(['certificate', 'private_key', 'fullchain', 'ca_bundle', 'issued_at', 'expires_at', 'domains']);
});

it('remainingDays returns approximate days until expiry', function () {
    $cert = makeCert([
        'expiresAt' => new DateTimeImmutable('+30 days'),
    ]);

    expect($cert->remainingDays())->toBeBetween(29, 31);
});

it('remainingDays returns zero for an expired certificate', function () {
    $cert = makeCert([
        'expiresAt' => new DateTimeImmutable('-1 day'),
    ]);

    expect($cert->remainingDays())->toBe(0);
});

it('preserves all domain entries', function () {
    $cert = makeCert(['domains' => ['example.com', 'www.example.com', '*.example.com']]);

    expect(StoredCertificate::fromArray($cert->toArray())->domains)
        ->toBe(['example.com', 'www.example.com', '*.example.com']);
});
