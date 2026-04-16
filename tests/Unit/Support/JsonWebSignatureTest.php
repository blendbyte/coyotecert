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
        $pem
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
        $pem
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

it('ecParams throws RuntimeException for unsupported EC curve', function () {
    // secp521r1 is not in the match — triggers the default RuntimeException branch
    $pem = ecKeyPem('secp521r1');

    expect(fn () => JsonWebSignature::generate([], 'https://example.com', 'nonce', $pem))
        ->toThrow(\RuntimeException::class, 'Unsupported EC curve: secp521r1');
});
