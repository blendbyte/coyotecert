<?php

use CoyoteCert\Enums\KeyType;

it('returns the correct JWS algorithm', function (KeyType $type, string $alg) {
    expect($type->jwsAlgorithm())->toBe($alg);
})->with([
    [KeyType::RSA_2048, 'RS256'],
    [KeyType::RSA_4096, 'RS256'],
    [KeyType::EC_P256,  'ES256'],
    [KeyType::EC_P384,  'ES384'],
]);

it('returns the correct bit count for RSA', function (KeyType $type, int $bits) {
    expect($type->bits())->toBe($bits);
})->with([
    [KeyType::RSA_2048, 2048],
    [KeyType::RSA_4096, 4096],
]);

it('returns null bits for EC types', function (KeyType $type) {
    expect($type->bits())->toBeNull();
})->with([[KeyType::EC_P256], [KeyType::EC_P384]]);

it('returns the correct curve name', function (KeyType $type, string $curve) {
    expect($type->curveName())->toBe($curve);
})->with([
    [KeyType::EC_P256, 'prime256v1'],
    [KeyType::EC_P384, 'secp384r1'],
]);

it('returns null curve name for RSA', function (KeyType $type) {
    expect($type->curveName())->toBeNull();
})->with([[KeyType::RSA_2048], [KeyType::RSA_4096]]);

it('correctly identifies RSA vs EC', function (KeyType $type, bool $isRsa, bool $isEc) {
    expect($type->isRsa())->toBe($isRsa);
    expect($type->isEc())->toBe($isEc);
})->with([
    [KeyType::RSA_2048, true,  false],
    [KeyType::RSA_4096, true,  false],
    [KeyType::EC_P256,  false, true],
    [KeyType::EC_P384,  false, true],
]);

it('returns the correct openssl key type constant', function (KeyType $type, int $const) {
    expect($type->openSslType())->toBe($const);
})->with([
    [KeyType::RSA_2048, OPENSSL_KEYTYPE_RSA],
    [KeyType::RSA_4096, OPENSSL_KEYTYPE_RSA],
    [KeyType::EC_P256,  OPENSSL_KEYTYPE_EC],
    [KeyType::EC_P384,  OPENSSL_KEYTYPE_EC],
]);
