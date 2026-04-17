<?php

namespace CoyoteCert\Enums;

enum KeyType: string
{
    case RSA_2048 = 'RSA_2048';
    case RSA_4096 = 'RSA_4096';
    case EC_P256  = 'EC_P256';
    case EC_P384  = 'EC_P384';

    public function jwsAlgorithm(): string
    {
        return match ($this) {
            self::RSA_2048, self::RSA_4096 => 'RS256',
            self::EC_P256                  => 'ES256',
            self::EC_P384                  => 'ES384',
        };
    }

    public function openSslType(): int
    {
        return match ($this) {
            self::RSA_2048, self::RSA_4096 => OPENSSL_KEYTYPE_RSA,
            self::EC_P256, self::EC_P384   => OPENSSL_KEYTYPE_EC,
        };
    }

    public function bits(): ?int
    {
        return match ($this) {
            self::RSA_2048               => 2048,
            self::RSA_4096               => 4096,
            self::EC_P256, self::EC_P384 => null,
        };
    }

    public function curveName(): ?string
    {
        return match ($this) {
            self::EC_P256 => 'prime256v1',
            self::EC_P384 => 'secp384r1',
            default       => null,
        };
    }

    public function isEc(): bool
    {
        return $this === self::EC_P256 || $this === self::EC_P384;
    }

    public function isRsa(): bool
    {
        return $this === self::RSA_2048 || $this === self::RSA_4096;
    }
}
