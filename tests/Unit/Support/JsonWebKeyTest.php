<?php

use CoyoteCert\Support\Base64;
use CoyoteCert\Support\JsonWebKey;

function rsaKeyPem(): string
{
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
        $pem
    );
    return $pem;
}

function ecKeyPem(string $curve = 'prime256v1'): string
{
    return match ($curve) {
        'prime256v1' => "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHaR0sCEL8isElEhAhPAsqrogUVVqP+uvX8Bf9zsjALqoAoGCCqGSM49\nAwEHoUQDQgAEN2q6j/MaE8CZ6KLmpR5ocW26YOXvVgiuIuIpouGek2Bu67BBpDRs\nG17vInzVc/P0R01RhthIrIahxR2OdxbkZw==\n-----END EC PRIVATE KEY-----",
        'secp384r1'  => "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDDgub3rNdQD28MtMUkOsFxxDIlS5mzPotXUzl/5IQLTd0oGtNdbovij\nV6H+2jzWT66gBwYFK4EEACKhZANiAAR+uI186ZeIR46EbYd7XRLWI4fotezzHLUS\noaF73Sp236v453E4W/V7QnMevfA3WtLnrhb7F1IATQLGO4f1skqmMSqHYXzRSLOW\nCejQifvrz0TqrkyVdK9e7uq36NPEDDw=\n-----END EC PRIVATE KEY-----",
        'secp521r1'  => "-----BEGIN EC PRIVATE KEY-----\nMIHcAgEBBEIBn7Elzxkr+b9LEKfx/wxC7/g+hqiiI+OsrXp4CGNOgiCy+B6yQFI8\nuUB41kdrTzsd0YFnDhiKkx256WDxap2rEs6gBwYFK4EEACOhgYkDgYYABADV+WWz\neq1sbiBK5IJkT4AcV14E8tw8h2uE7Oz3RHF//MoGQlAeZJZ2a/e5nrzbCxVV8ySz\nNsWw/Ye7ErDbvPZb6gCxUemjdn7hVHrnbqoDgDJXlcSI0QtSHQcb3C9ifjxCqhvl\nhzyCoKJdVpqaJk8ArxBh1sLbDLrXREZyXseGAWjteQ==\n-----END EC PRIVATE KEY-----",
        default      => throw new \InvalidArgumentException("Unknown curve: $curve"),
    };
}

it('computes an RSA JWK with e, kty, n', function () {
    $jwk = JsonWebKey::compute(rsaKeyPem());

    expect($jwk)->toHaveKeys(['e', 'kty', 'n']);
    expect($jwk['kty'])->toBe('RSA');
    expect($jwk['e'])->toBeString()->not->toBeEmpty();
    expect($jwk['n'])->toBeString()->not->toBeEmpty();
});

it('RSA JWK keys are in lexicographic order for correct thumbprint', function () {
    $jwk = JsonWebKey::compute(rsaKeyPem());

    expect(array_keys($jwk))->toBe(['e', 'kty', 'n']);
});

it('computes an EC P-256 JWK with crv, kty, x, y', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('prime256v1'));

    expect($jwk)->toHaveKeys(['crv', 'kty', 'x', 'y']);
    expect($jwk['kty'])->toBe('EC');
    expect($jwk['crv'])->toBe('P-256');
    expect($jwk['x'])->toBeString()->not->toBeEmpty();
    expect($jwk['y'])->toBeString()->not->toBeEmpty();
});

it('EC P-256 coordinates are padded to 32 bytes', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('prime256v1'));

    expect(strlen(Base64::urlSafeDecode($jwk['x'])))->toBe(32);
    expect(strlen(Base64::urlSafeDecode($jwk['y'])))->toBe(32);
});

it('computes an EC P-384 JWK with crv P-384', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('secp384r1'));

    expect($jwk['crv'])->toBe('P-384');
    expect(strlen(Base64::urlSafeDecode($jwk['x'])))->toBe(48);
    expect(strlen(Base64::urlSafeDecode($jwk['y'])))->toBe(48);
});

it('EC JWK keys are in lexicographic order for correct thumbprint', function () {
    $jwk = JsonWebKey::compute(ecKeyPem('prime256v1'));

    expect(array_keys($jwk))->toBe(['crv', 'kty', 'x', 'y']);
});

it('thumbprint returns a non-empty base64url string', function () {
    $jwk       = JsonWebKey::compute(rsaKeyPem());
    $thumbprint = JsonWebKey::thumbprint($jwk);

    expect($thumbprint)->toBeString()->not->toBeEmpty();
    expect($thumbprint)->not->toContain('=');
    expect($thumbprint)->not->toContain('+');
    expect($thumbprint)->not->toContain('/');
});

it('throws for an unsupported EC curve', function () {
    expect(fn () => JsonWebKey::compute(ecKeyPem('secp521r1')))
        ->toThrow(\CoyoteCert\Exceptions\LetsEncryptClientException::class);
});
