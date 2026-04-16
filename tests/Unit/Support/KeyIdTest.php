<?php

use CoyoteCert\Support\Base64;
use CoyoteCert\Support\KeyId;

it('generates an RS256 KID JWS with kid, alg, nonce, url', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem
    );

    $result    = KeyId::generate($pem, 'https://acme.example/account/1', 'https://acme.example/order/1', 'nonce1');
    $protected = json_decode(Base64::urlSafeDecode($result['protected']), true);

    expect($protected['alg'])->toBe('RS256');
    expect($protected['kid'])->toBe('https://acme.example/account/1');
    expect($protected['url'])->toBe('https://acme.example/order/1');
    expect($protected['nonce'])->toBe('nonce1');
});

it('produces a verifiable RS256 KID signature', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem
    );

    $result       = KeyId::generate($pem, 'https://example.com/account/1', 'https://example.com/order/1', 'nonce', ['csr' => 'abc']);
    $signingInput = $result['protected'] . '.' . $result['payload'];
    $sig          = Base64::urlSafeDecode($result['signature']);
    $pubKey       = openssl_pkey_get_details(openssl_pkey_get_private($pem))['key'];

    expect(openssl_verify($signingInput, $sig, $pubKey, 'SHA256'))->toBe(1);
});

it('generates an ES256 KID JWS', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHaR0sCEL8isElEhAhPAsqrogUVVqP+uvX8Bf9zsjALqoAoGCCqGSM49\nAwEHoUQDQgAEN2q6j/MaE8CZ6KLmpR5ocW26YOXvVgiuIuIpouGek2Bu67BBpDRs\nG17vInzVc/P0R01RhthIrIahxR2OdxbkZw==\n-----END EC PRIVATE KEY-----";

    $result    = KeyId::generate($pem, 'https://acme.example/account/1', 'https://acme.example/order/1', 'nonce');
    $protected = json_decode(Base64::urlSafeDecode($result['protected']), true);

    expect($protected['alg'])->toBe('ES256');
});

it('produces a verifiable ES256 KID signature', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHaR0sCEL8isElEhAhPAsqrogUVVqP+uvX8Bf9zsjALqoAoGCCqGSM49\nAwEHoUQDQgAEN2q6j/MaE8CZ6KLmpR5ocW26YOXvVgiuIuIpouGek2Bu67BBpDRs\nG17vInzVc/P0R01RhthIrIahxR2OdxbkZw==\n-----END EC PRIVATE KEY-----";

    $result       = KeyId::generate($pem, 'https://example.com/account/1', 'https://example.com/order/1', 'nonce', ['foo' => 'bar']);
    $signingInput = $result['protected'] . '.' . $result['payload'];
    $rawSig       = Base64::urlSafeDecode($result['signature']);

    // Convert raw r||s back to DER for openssl_verify
    $r = ltrim(substr($rawSig, 0, 32), "\x00") ?: "\x00";
    $s = ltrim(substr($rawSig, 32), "\x00") ?: "\x00";
    if (ord($r[0]) > 0x7F) $r = "\x00" . $r;
    if (ord($s[0]) > 0x7F) $s = "\x00" . $s;
    $inner  = "\x02" . chr(strlen($r)) . $r . "\x02" . chr(strlen($s)) . $s;
    $derSig = "\x30" . chr(strlen($inner)) . $inner;

    $pubKey = openssl_pkey_get_details(openssl_pkey_get_private($pem))['key'];

    expect(openssl_verify($signingInput, $derSig, $pubKey, 'SHA256'))->toBe(1);
});

it('uses an empty payload string for POST-as-GET (null payload)', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem
    );

    $result = KeyId::generate($pem, 'https://example.com/account/1', 'https://example.com/order/1', 'nonce');

    // base64url('') = ''
    expect($result['payload'])->toBe('');
});

it('generates an ES384 KID JWS for secp384r1 keys', function () {
    $pem = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDDgub3rNdQD28MtMUkOsFxxDIlS5mzPotXUzl/5IQLTd0oGtNdbovij\nV6H+2jzWT66gBwYFK4EEACKhZANiAAR+uI186ZeIR46EbYd7XRLWI4fotezzHLUS\noaF73Sp236v453E4W/V7QnMevfA3WtLnrhb7F1IATQLGO4f1skqmMSqHYXzRSLOW\nCejQifvrz0TqrkyVdK9e7uq36NPEDDw=\n-----END EC PRIVATE KEY-----";

    $result    = KeyId::generate($pem, 'https://acme.example/account/1', 'https://acme.example/order/1', 'nonce');
    $protected = json_decode(Base64::urlSafeDecode($result['protected']), true);

    expect($protected['alg'])->toBe('ES384');
});

it('encodes an empty array payload as {} (RFC 8555 §7.5.1 challenge response)', function () {
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem
    );

    $result  = KeyId::generate($pem, 'https://example.com/account/1', 'https://example.com/order/1', 'nonce', []);
    $payload = Base64::urlSafeDecode($result['payload']);

    expect($payload)->toBe('{}');
});

it('ecParams throws RuntimeException for unsupported EC curve', function () {
    // secp521r1 is not in the match — triggers the default RuntimeException branch
    $pem = ecKeyPem('secp521r1');

    expect(fn () => \CoyoteCert\Support\KeyId::generate($pem, 'https://example.com/account/1', 'https://example.com/order/1', 'nonce'))
        ->toThrow(\RuntimeException::class, 'Unsupported EC curve: secp521r1');
});

