<?php

use CoyoteCert\Support\Base64;
use CoyoteCert\Support\JsonWebSignature;

/**
 * Convert a raw r||s ECDSA signature back to DER so openssl_verify can consume it.
 */
function rawSigToDer(string $raw, int $componentLen): string
{
    $r = ltrim(substr($raw, 0, $componentLen), "\x00") ?: "\x00";
    $s = ltrim(substr($raw, $componentLen), "\x00") ?: "\x00";

    if (ord($r[0]) > 0x7F) {
        $r = "\x00" . $r;
    }
    if (ord($s[0]) > 0x7F) {
        $s = "\x00" . $s;
    }

    $inner = "\x02" . chr(strlen($r)) . $r . "\x02" . chr(strlen($s)) . $s;

    return "\x30" . chr(strlen($inner)) . $inner;
}

it('generates an RS256 JWS with the correct protected header', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem,
    );

    $result    = JsonWebSignature::generate(['foo' => 'bar'], 'https://acme.example/new-account', 'nonce123', $pem);
    $protected = json_decode(Base64::urlSafeDecode($result['protected']), true);

    expect($protected['alg'])->toBe('RS256');
    expect($protected['nonce'])->toBe('nonce123');
    expect($protected['url'])->toBe('https://acme.example/new-account');
    expect($protected['jwk']['kty'])->toBe('RSA');
});

it('produces a verifiable RS256 signature', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem,
    );

    $result       = JsonWebSignature::generate(['test' => 1], 'https://example.com', 'nonce', $pem);
    $signingInput = $result['protected'] . '.' . $result['payload'];
    $sig          = Base64::urlSafeDecode($result['signature']);
    $pubKey       = openssl_pkey_get_details(openssl_pkey_get_private($pem))['key'];

    expect(openssl_verify($signingInput, $sig, $pubKey, 'SHA256'))->toBe(1);
});

it('generates an ES256 JWS with the correct protected header', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHaR0sCEL8isElEhAhPAsqrogUVVqP+uvX8Bf9zsjALqoAoGCCqGSM49\nAwEHoUQDQgAEN2q6j/MaE8CZ6KLmpR5ocW26YOXvVgiuIuIpouGek2Bu67BBpDRs\nG17vInzVc/P0R01RhthIrIahxR2OdxbkZw==\n-----END EC PRIVATE KEY-----";

    $result    = JsonWebSignature::generate(['foo' => 'bar'], 'https://acme.example/new-account', 'nonce123', $pem);
    $protected = json_decode(Base64::urlSafeDecode($result['protected']), true);

    expect($protected['alg'])->toBe('ES256');
    expect($protected['jwk']['kty'])->toBe('EC');
    expect($protected['jwk']['crv'])->toBe('P-256');
});

it('produces a verifiable ES256 signature', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHaR0sCEL8isElEhAhPAsqrogUVVqP+uvX8Bf9zsjALqoAoGCCqGSM49\nAwEHoUQDQgAEN2q6j/MaE8CZ6KLmpR5ocW26YOXvVgiuIuIpouGek2Bu67BBpDRs\nG17vInzVc/P0R01RhthIrIahxR2OdxbkZw==\n-----END EC PRIVATE KEY-----";

    $result       = JsonWebSignature::generate(['test' => 1], 'https://example.com', 'nonce', $pem);
    $signingInput = $result['protected'] . '.' . $result['payload'];
    $rawSig       = Base64::urlSafeDecode($result['signature']);
    $derSig       = rawSigToDer($rawSig, 32);
    $pubKey       = openssl_pkey_get_details(openssl_pkey_get_private($pem))['key'];

    expect(openssl_verify($signingInput, $derSig, $pubKey, 'SHA256'))->toBe(1);
});

it('generates an ES384 JWS with the correct algorithm', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDDgub3rNdQD28MtMUkOsFxxDIlS5mzPotXUzl/5IQLTd0oGtNdbovij\nV6H+2jzWT66gBwYFK4EEACKhZANiAAR+uI186ZeIR46EbYd7XRLWI4fotezzHLUS\noaF73Sp236v453E4W/V7QnMevfA3WtLnrhb7F1IATQLGO4f1skqmMSqHYXzRSLOW\nCejQifvrz0TqrkyVdK9e7uq36NPEDDw=\n-----END EC PRIVATE KEY-----";

    $result    = JsonWebSignature::generate([], 'https://example.com', 'nonce', $pem);
    $protected = json_decode(Base64::urlSafeDecode($result['protected']), true);

    expect($protected['alg'])->toBe('ES384');
    expect($protected['jwk']['crv'])->toBe('P-384');
});

it('produces a verifiable ES384 signature', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDDgub3rNdQD28MtMUkOsFxxDIlS5mzPotXUzl/5IQLTd0oGtNdbovij\nV6H+2jzWT66gBwYFK4EEACKhZANiAAR+uI186ZeIR46EbYd7XRLWI4fotezzHLUS\noaF73Sp236v453E4W/V7QnMevfA3WtLnrhb7F1IATQLGO4f1skqmMSqHYXzRSLOW\nCejQifvrz0TqrkyVdK9e7uq36NPEDDw=\n-----END EC PRIVATE KEY-----";

    $result       = JsonWebSignature::generate(['test' => 1], 'https://example.com', 'nonce', $pem);
    $signingInput = $result['protected'] . '.' . $result['payload'];
    $rawSig       = Base64::urlSafeDecode($result['signature']);
    $derSig       = rawSigToDer($rawSig, 48);
    $pubKey       = openssl_pkey_get_details(openssl_pkey_get_private($pem))['key'];

    expect(openssl_verify($signingInput, $derSig, $pubKey, 'SHA384'))->toBe(1);
});

it('throws CryptoException when the private key PEM is invalid', function () {
    expect(fn() => JsonWebSignature::generate([], 'https://example.com', 'nonce', 'not-a-pem'))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Cannot load private key');
});

it('ecParams throws CryptoException for unsupported EC curve', function () {
    // secp521r1 is not in the match — triggers the default RuntimeException branch
    $pem = ecKeyPem('secp521r1');

    expect(fn() => JsonWebSignature::generate([], 'https://example.com', 'nonce', $pem))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Unsupported EC curve: secp521r1');
});

// ── EcSigning::ecParamsFromKey() ──────────────────────────────────────────────

it('EcSigning::ecParamsFromKey() returns crv/x/y for a P-256 key', function () {
    $key    = openssl_pkey_get_private(ecKeyPem('prime256v1'));
    $params = \CoyoteCert\Support\EcSigning::ecParamsFromKey($key);

    expect($params['crv'])->toBe('P-256');
    expect($params)->toHaveKey('x');
    expect($params)->toHaveKey('y');
});

it('EcSigning::ecParamsFromKey() returns crv/x/y for a P-384 key', function () {
    $key    = openssl_pkey_get_private(ecKeyPem('secp384r1'));
    $params = \CoyoteCert\Support\EcSigning::ecParamsFromKey($key);

    expect($params['crv'])->toBe('P-384');
});

it('EcSigning::ecParamsFromKey() throws CryptoException for a non-EC key', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $rsaPem,
    );
    $rsaKey = openssl_pkey_get_private($rsaPem);

    expect(fn() => \CoyoteCert\Support\EcSigning::ecParamsFromKey($rsaKey))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Key is not an EC key.');
});

it('EcSigning::ecParamsFromKey() throws CryptoException for an unsupported EC curve', function () {
    $key = openssl_pkey_get_private(ecKeyPem('secp521r1'));

    expect(fn() => \CoyoteCert\Support\EcSigning::ecParamsFromKey($key))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Unsupported EC curve');
});

// ── SEC-10: EcSigning::derToRaw() bounds checking ────────────────────────────

it('derToRaw() throws CryptoException for an empty string', function () {
    expect(fn () => \CoyoteCert\Support\EcSigning::derToRaw('', 32))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Malformed DER');
});

it('derToRaw() throws CryptoException when first byte is not 0x30', function () {
    expect(fn () => \CoyoteCert\Support\EcSigning::derToRaw("\x02\x04\x02\x01\x01\x02\x01\x01", 32))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Malformed DER');
});

it('derToRaw() throws CryptoException when R tag byte is not 0x02', function () {
    // 0x30 [seq-len] 0x99 [r-len] ... — wrong R tag
    expect(fn () => \CoyoteCert\Support\EcSigning::derToRaw("\x30\x06\x99\x01\x01\x02\x01\x01", 32))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Malformed DER');
});

it('derToRaw() throws CryptoException when R length overflows the buffer', function () {
    // R claims length 100 but buffer is only 8 bytes
    expect(fn () => \CoyoteCert\Support\EcSigning::derToRaw("\x30\x06\x02\x64\x01\x02\x01\x01", 32))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Malformed DER');
});

it('derToRaw() throws CryptoException when S length overflows the buffer', function () {
    // Valid R (1 byte), but S claims length 100
    expect(fn () => \CoyoteCert\Support\EcSigning::derToRaw("\x30\x06\x02\x01\x01\x02\x64\x01", 32))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Malformed DER');
});

it('derToRaw() correctly converts a real P-256 DER signature', function () {
    // Generate a real signature and round-trip it through derToRaw() → rawSigToDer()
    $pem  = ecKeyPem('prime256v1');
    $key  = openssl_pkey_get_private($pem);
    openssl_sign('test-data', $der, $key, 'SHA256');

    $raw = \CoyoteCert\Support\EcSigning::derToRaw($der, 32);
    expect(strlen($raw))->toBe(64);

    // Re-encode as DER and verify the signature is still valid
    $reDer  = rawSigToDer($raw, 32);
    $pubKey = openssl_pkey_get_details($key)['key'];
    expect(openssl_verify('test-data', $reDer, $pubKey, 'SHA256'))->toBe(1);
});
