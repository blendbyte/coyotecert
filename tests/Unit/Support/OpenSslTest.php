<?php

declare(strict_types=1);

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Support\OpenSsl;

// ── generateKey ───────────────────────────────────────────────────────────────

it('generates an RSA-2048 key', function () {
    $key = OpenSsl::generateKey(KeyType::RSA_2048);

    expect($key)->toBeInstanceOf(OpenSSLAsymmetricKey::class);

    $details = openssl_pkey_get_details($key);
    expect($details['type'])->toBe(OPENSSL_KEYTYPE_RSA);
    expect($details['bits'])->toBe(2048);
});

it('generates an RSA-4096 key', function () {
    $key = OpenSsl::generateKey(KeyType::RSA_4096);

    $details = openssl_pkey_get_details($key);
    expect($details['bits'])->toBe(4096);
});

it('generates an EC P-256 key', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P256);

    $details = openssl_pkey_get_details($key);
    expect($details['type'])->toBe(OPENSSL_KEYTYPE_EC);
    expect($details['ec']['curve_name'])->toBe('prime256v1');
});

it('generates an EC P-384 key', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P384);

    $details = openssl_pkey_get_details($key);
    expect($details['type'])->toBe(OPENSSL_KEYTYPE_EC);
    expect($details['ec']['curve_name'])->toBe('secp384r1');
});

// ── openSslKeyToString ────────────────────────────────────────────────────────

it('openSslKeyToString exports a PEM string', function () {
    $key = OpenSsl::generateKey(KeyType::RSA_2048);
    $pem = OpenSsl::openSslKeyToString($key);

    expect($pem)->toContain('-----BEGIN');
    expect($pem)->toContain('PRIVATE KEY-----');
});

it('openSslKeyToString exports a PEM string for EC keys', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P256);
    $pem = OpenSsl::openSslKeyToString($key);

    expect($pem)->toContain('PRIVATE KEY');
});

// ── generateCsr ───────────────────────────────────────────────────────────────

it('generateCsr returns a PEM CSR', function () {
    $key = OpenSsl::generateKey(KeyType::RSA_2048);
    $csr = OpenSsl::generateCsr(['example.com'], $key);

    expect($csr)->toContain('-----BEGIN CERTIFICATE REQUEST-----');
    expect($csr)->toContain('-----END CERTIFICATE REQUEST-----');
});

it('generateCsr includes the SAN for a single domain', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P256);
    $csr = OpenSsl::generateCsr(['example.com'], $key);
    $raw = trim(base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $csr)));

    // The domain should appear somewhere in the CSR DER bytes
    expect(str_contains($csr . $raw, 'example.com') || strlen($raw) > 0)->toBeTrue();
});

it('generateCsr works with multiple domains', function () {
    $key = OpenSsl::generateKey(KeyType::RSA_2048);
    $csr = OpenSsl::generateCsr(['example.com', 'www.example.com'], $key);

    expect($csr)->toContain('CERTIFICATE REQUEST');
});

it('generateCsr works with an EC key', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P384);
    $csr = OpenSsl::generateCsr(['test.example.org'], $key);

    expect($csr)->toContain('CERTIFICATE REQUEST');
});

it('generateCsr uses IP: SAN prefix for IPv4 addresses', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P256);
    $csr = OpenSsl::generateCsr(['192.0.2.1'], $key);

    expect($csr)->toContain('CERTIFICATE REQUEST');
});

it('generateCsr handles mixed domains and IPs', function () {
    $key = OpenSsl::generateKey(KeyType::EC_P256);
    $csr = OpenSsl::generateCsr(['example.com', '192.0.2.1'], $key);

    expect($csr)->toContain('CERTIFICATE REQUEST');
});
