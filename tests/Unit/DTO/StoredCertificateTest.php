<?php

use CoyoteCert\Storage\StoredCertificate;

function makeCert(array $overrides = []): StoredCertificate
{
    return new StoredCertificate(
        certificate: $overrides['certificate'] ?? 'cert-pem',
        privateKey: $overrides['privateKey']   ?? 'key-pem',
        fullchain: $overrides['fullchain']     ?? 'fullchain-pem',
        caBundle: $overrides['caBundle']       ?? 'ca-bundle-pem',
        issuedAt: $overrides['issuedAt']       ?? new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
        expiresAt: $overrides['expiresAt']     ?? new DateTimeImmutable('2026-04-01T00:00:00+00:00'),
        domains: $overrides['domains']         ?? ['example.com'],
    );
}

/**
 * Generate a self-signed certificate whose v3 extensions are set via a
 * temporary openssl config file.  Returns the PEM string.
 *
 * @param string[] $sans DNS names to include in subjectAltName
 * @param bool $withAki Whether to add authorityKeyIdentifier
 * @param int $serial Certificate serial (use odd-length-safe values)
 */
function makeStoredCertPem(
    array  $sans = ['example.com'],
    bool   $withAki = false,
    int    $serial = 1,
    string $cn = 'example.com',
): string {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => $cn], $key);

    $sanList    = implode(', ', array_map(fn($d) => 'DNS:' . $d, $sans));
    $akiSection = $withAki ? "authorityKeyIdentifier = keyid:always\n" : '';

    $configContent = <<<CFG
        [ req ]
        [ req_distinguished_name ]
        [ v3 ]
        subjectAltName = {$sanList}
        subjectKeyIdentifier = hash
        {$akiSection}
        CFG;

    $tmpFile = tmpfile();
    fwrite($tmpFile, $configContent);
    $configPath = stream_get_meta_data($tmpFile)['uri'];

    $cert = openssl_csr_sign(
        $csr,
        null,
        $key,
        365,
        ['config' => $configPath, 'x509_extensions' => 'v3'],
        serial: $serial,
    );

    fclose($tmpFile);

    openssl_x509_export($cert, $pem);

    return $pem;
}

/**
 * Generate a CA→leaf chain where the leaf has AKI pointing to the CA.
 * Returns [leafPem, caPem].
 */
function makeStoredCertWithAki(): array
{
    $caKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $caCsr = openssl_csr_new(['commonName' => 'Test CA'], $caKey);

    $caTmp = tmpfile();
    fwrite($caTmp, "[ req ]\n[ req_distinguished_name ]\n[ v3_ca ]\nsubjectKeyIdentifier = hash\nbasicConstraints = CA:true\n");
    $caCert = openssl_csr_sign($caCsr, null, $caKey, 3650, ['config' => stream_get_meta_data($caTmp)['uri'], 'x509_extensions' => 'v3_ca'], serial: 1);

    $leafKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $leafCsr = openssl_csr_new(['commonName' => 'leaf.example.com'], $leafKey);

    $leafTmp = tmpfile();
    fwrite($leafTmp, "[ req ]\n[ req_distinguished_name ]\n[ v3_leaf ]\nsubjectAltName = DNS:leaf.example.com\nauthorityKeyIdentifier = keyid:always\n");
    $leafCert = openssl_csr_sign($leafCsr, $caCert, $caKey, 365, ['config' => stream_get_meta_data($leafTmp)['uri'], 'x509_extensions' => 'v3_leaf'], serial: 1);

    fclose($caTmp);
    fclose($leafTmp);

    openssl_x509_export($leafCert, $leafPem);
    openssl_x509_export($caCert, $caPem);

    return [$leafPem, $caPem];
}

// ── Existing tests ────────────────────────────────────────────────────────────

it('roundtrips through toArray/fromArray', function () {
    $cert = makeCert();

    expect(StoredCertificate::fromArray($cert->toArray())->toArray())->toBe($cert->toArray());
});

it('toArray contains all expected keys', function () {
    $data = makeCert()->toArray();

    expect($data)->toHaveKeys(['certificate', 'private_key', 'fullchain', 'ca_bundle', 'issued_at', 'expires_at', 'domains', 'key_type']);
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

// ── sans() ────────────────────────────────────────────────────────────────────

it('sans() returns DNS names from the subjectAltName extension', function () {
    $pem  = makeStoredCertPem(['example.com', 'www.example.com']);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->sans())->toBe(['example.com', 'www.example.com']);
});

it('sans() returns a single domain when only one SAN is present', function () {
    $pem  = makeStoredCertPem(['only.example.com']);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->sans())->toBe(['only.example.com']);
});

it('sans() returns an empty array when the certificate has no SAN extension', function () {
    // makeCert() uses a dummy PEM string — openssl_x509_parse() returns false/[]
    // so the fallback empty-string path is exercised
    $cert = makeCert(['certificate' => 'not-a-real-cert']);

    expect($cert->sans())->toBe([]);
});

// ── serialNumber() ────────────────────────────────────────────────────────────

it('serialNumber() returns the lowercase hex serial', function () {
    $pem  = makeStoredCertPem(serial: 1);   // serial 1 → hex '01'
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->serialNumber())->toBe('01');
});

it('serialNumber() returns an empty string for an unparseable certificate', function () {
    $cert = makeCert(['certificate' => 'not-a-real-cert']);

    expect($cert->serialNumber())->toBe('');
});

// ── authorityKeyId() ──────────────────────────────────────────────────────────

it('authorityKeyId() returns null when the extension is absent', function () {
    // A self-signed cert generated without authorityKeyIdentifier in the config
    $pem  = makeStoredCertPem(withAki: false);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->authorityKeyId())->toBeNull();
});

it('authorityKeyId() returns an uppercase colon-separated hex string when present', function () {
    [$leafPem] = makeStoredCertWithAki();
    $cert      = makeCert(['certificate' => $leafPem]);

    $aki = $cert->authorityKeyId();

    expect($aki)->toBeString();
    // Format: "XX:XX:XX:..." — each octet is two hex digits, separated by colons
    expect($aki)->toMatch('/^[0-9A-F]{2}(:[0-9A-F]{2})+$/');
});

it('authorityKeyId() returns null for an unparseable certificate', function () {
    $cert = makeCert(['certificate' => 'not-a-real-cert']);

    expect($cert->authorityKeyId())->toBeNull();
});

// ── issuer() ──────────────────────────────────────────────────────────────────

it('issuer() returns the issuer DN as an array', function () {
    $pem  = makeStoredCertPem(cn: 'Test Issuer');
    $cert = makeCert(['certificate' => $pem]);

    $issuer = $cert->issuer();

    expect($issuer)->toBeArray();
    expect($issuer)->toHaveKey('CN');
    expect($issuer['CN'])->toBe('Test Issuer');
});

it('issuer() returns an empty array for an unparseable certificate', function () {
    $cert = makeCert(['certificate' => 'not-a-real-cert']);

    expect($cert->issuer())->toBe([]);
});

// ── authorityKeyId() ──────────────────────────────────────────────────────────

it('authorityKeyId() returns a colon-separated hex key ID for a cert with AKI extension', function () {
    $pem  = makeStoredCertPem(withAki: true);
    $cert = makeCert(['certificate' => $pem]);

    $aki = $cert->authorityKeyId();

    // keyid:always extension → should produce a "XX:XX:XX..." string
    expect($aki)->not->toBeNull();
    expect($aki)->toBeString();
    expect($aki)->toMatch('/^[0-9A-F]{2}(:[0-9A-F]{2})*$/');
});

it('authorityKeyId() returns null for a cert without AKI extension', function () {
    $pem  = makeStoredCertPem(withAki: false); // no authorityKeyIdentifier
    $cert = makeCert(['certificate' => $pem]);

    // Not all self-signed certs include AKI — expect null when the ext is absent
    $aki = $cert->authorityKeyId();
    expect($aki)->toBeNull();
});

// ── daysUntilExpiry() ─────────────────────────────────────────────────────────

it('daysUntilExpiry() returns a positive integer for a future certificate', function () {
    $cert = makeCert([
        'expiresAt' => new DateTimeImmutable('+30 days'),
    ]);

    expect($cert->daysUntilExpiry())->toBeGreaterThan(0);
    expect($cert->daysUntilExpiry())->toBeBetween(29, 31);
});

it('daysUntilExpiry() returns a negative value for an expired certificate', function () {
    $cert = makeCert([
        'expiresAt' => new DateTimeImmutable('-10 days'),
    ]);

    expect($cert->daysUntilExpiry())->toBeLessThan(0);
});

it('daysUntilExpiry() uses ceiling so a partial day counts as a full day', function () {
    // Expire in slightly more than 1 day: result should be 2 (ceiling)
    $cert = makeCert([
        'expiresAt' => new DateTimeImmutable('+1 day +1 second'),
    ]);

    expect($cert->daysUntilExpiry())->toBe(2);
});

it('daysUntilExpiry() returns 0 or 1 for a cert expiring within the next day', function () {
    $cert = makeCert([
        'expiresAt' => new DateTimeImmutable('+1 hour'),
    ]);

    expect($cert->daysUntilExpiry())->toBeBetween(0, 1);
});

// ── isValidForDomains() ───────────────────────────────────────────────────────

it('isValidForDomains() returns true when requested domains are in the SAN', function () {
    $pem  = makeStoredCertPem(['example.com', 'www.example.com']);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->isValidForDomains(['example.com']))->toBeTrue();
    expect($cert->isValidForDomains(['www.example.com']))->toBeTrue();
    expect($cert->isValidForDomains(['example.com', 'www.example.com']))->toBeTrue();
});

it('isValidForDomains() returns false when a domain is not in the SAN', function () {
    $pem  = makeStoredCertPem(['example.com']);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->isValidForDomains(['other.com']))->toBeFalse();
});

it('isValidForDomains() returns true when a wildcard SAN covers the domain', function () {
    $pem  = makeStoredCertPem(['*.example.com']);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->isValidForDomains(['sub.example.com']))->toBeTrue();
});

it('isValidForDomains() wildcard does NOT cover the apex domain itself', function () {
    $pem  = makeStoredCertPem(['*.example.com']);
    $cert = makeCert(['certificate' => $pem]);

    // *.example.com does not cover example.com (RFC 2818 §3.1)
    expect($cert->isValidForDomains(['example.com']))->toBeFalse();
});

it('isValidForDomains() returns false when one of several requested domains is missing', function () {
    $pem  = makeStoredCertPem(['example.com']);
    $cert = makeCert(['certificate' => $pem]);

    expect($cert->isValidForDomains(['example.com', 'missing.com']))->toBeFalse();
});
