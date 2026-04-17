<?php

use CoyoteCert\Challenge\TlsAlpn01Handler;
use CoyoteCert\Enums\AuthorizationChallengeEnum;

// Concrete subclass for testing the abstract base
class TestTlsAlpn01Handler extends TlsAlpn01Handler
{
    public array $deployed = [];
    public array $cleaned  = [];

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->deployed[] = compact('domain', 'token', 'keyAuthorization');
    }

    public function cleanup(string $domain, string $token): void
    {
        $this->cleaned[] = compact('domain', 'token');
    }

    public function exposedGenerateAcmeCertificate(string $domain, string $keyAuthorization): array
    {
        return $this->generateAcmeCertificate($domain, $keyAuthorization);
    }
}

it('supports the tls-alpn-01 challenge type', function () {
    $handler = new TestTlsAlpn01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::TLS_ALPN))->toBeTrue();
});

it('does not support http-01', function () {
    $handler = new TestTlsAlpn01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::HTTP))->toBeFalse();
});

it('does not support dns-01', function () {
    $handler = new TestTlsAlpn01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::DNS))->toBeFalse();
});

it('does not support dns-persist-01', function () {
    $handler = new TestTlsAlpn01Handler();
    expect($handler->supports(AuthorizationChallengeEnum::DNS_PERSIST))->toBeFalse();
});

it('deploy is called and records the arguments', function () {
    $handler = new TestTlsAlpn01Handler();
    $handler->deploy('example.com', 'tok123', 'tok123.thumbprint');

    expect($handler->deployed)->toHaveCount(1);
    expect($handler->deployed[0]['domain'])->toBe('example.com');
    expect($handler->deployed[0]['token'])->toBe('tok123');
    expect($handler->deployed[0]['keyAuthorization'])->toBe('tok123.thumbprint');
});

it('cleanup is called and records the arguments', function () {
    $handler = new TestTlsAlpn01Handler();
    $handler->deploy('example.com', 'tok123', 'tok123.thumbprint');
    $handler->cleanup('example.com', 'tok123');

    expect($handler->cleaned)->toHaveCount(1);
    expect($handler->cleaned[0]['domain'])->toBe('example.com');
    expect($handler->cleaned[0]['token'])->toBe('tok123');
});

it('generateAcmeCertificate returns a PEM certificate and key', function () {
    $handler = new TestTlsAlpn01Handler();
    $result  = $handler->exposedGenerateAcmeCertificate('example.com', 'token123.thumbprintabc');

    expect($result)->toHaveKeys(['cert', 'key']);
    expect($result['cert'])->toContain('-----BEGIN CERTIFICATE-----');
    expect($result['key'])->toContain('-----BEGIN');
});

it('generateAcmeCertificate produces a self-signed certificate for the domain', function () {
    $handler = new TestTlsAlpn01Handler();
    $result  = $handler->exposedGenerateAcmeCertificate('example.com', 'token.thumbprint');

    $parsed = openssl_x509_parse($result['cert']);
    expect($parsed)->toBeArray();

    // Subject CN must match the domain
    expect($parsed['subject']['CN'] ?? '')->toBe('example.com');
});

it('generateAcmeCertificate embeds the acme-identifier extension OID', function () {
    $handler = new TestTlsAlpn01Handler();
    $result  = $handler->exposedGenerateAcmeCertificate('example.com', 'mytoken.mythumbprint');

    // Parse DER to look for the OID bytes of 1.3.6.1.5.5.7.1.31
    $der = base64_decode(
        preg_replace('/-----[^-]+-----|[\r\n\s]+/', '', $result['cert']),
    );

    // OID 1.3.6.1.5.5.7.1.31 encodes to: 2b 06 01 05 05 07 01 1f
    $oidBytes = "\x2b\x06\x01\x05\x05\x07\x01\x1f";
    expect(str_contains($der, $oidBytes))->toBeTrue();
});

it('generateAcmeCertificate produces a different cert for a different key authorization', function () {
    $handler = new TestTlsAlpn01Handler();
    $a       = $handler->exposedGenerateAcmeCertificate('example.com', 'token1.thumb');
    $b       = $handler->exposedGenerateAcmeCertificate('example.com', 'token2.thumb');

    expect($a['cert'])->not->toBe($b['cert']);
});
