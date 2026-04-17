# coyote-cert

[![Latest Version on Packagist](https://img.shields.io/packagist/v/blendbyte/coyotecert.svg?style=flat-square)](https://packagist.org/packages/blendbyte/coyotecert)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://github.com/blendbyte/coyotecert/blob/main/LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-787cb5?style=flat-square)](https://www.php.net)
[![Tests](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/tests.yml?branch=main&style=flat-square&label=tests)](https://github.com/blendbyte/coyotecert/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/codecov/c/github/blendbyte/coyotecert?style=flat-square)](https://codecov.io/gh/blendbyte/coyotecert)

ACME v2 PHP library for issuing, renewing, and revoking TLS certificates from Let's Encrypt and any other RFC 8555-compliant CA.

## Requirements

- PHP ^8.3
- `ext-curl`, `ext-json`, `ext-mbstring`, `ext-openssl`

## Installation

```bash
composer require blendbyte/coyotecert
```

## Quick start

```php
use CoyoteCert\CoyoteCert;
use CoyoteCert\Challenge\Http01Handler;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->domains('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issue();

echo $cert->certificate; // PEM-encoded certificate
echo $cert->privateKey;  // PEM-encoded private key
echo $cert->fullchain;   // certificate + intermediates
```

## Providers

| Provider | EAB required | Notes |
|---|---|---|
| `LetsEncrypt` | No | Production |
| `LetsEncryptStaging` | No | Testing — not browser-trusted |
| `ZeroSSL` | Yes | API key for auto-provisioning, or manual credentials |
| `BuypassGo` | No | |
| `BuypassGoStaging` | No | Testing |
| `GoogleTrustServices` | Yes | Credentials from Google Cloud Console |
| `SslCom` | Yes | RSA and ECC endpoints |
| `CustomProvider` | Optional | Any ACME-compliant CA |

### Let's Encrypt

```php
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;

new LetsEncrypt()
new LetsEncryptStaging()  // safe for testing
```

### ZeroSSL

```php
use CoyoteCert\Provider\ZeroSSL;

// Automatic EAB provisioning via API key (from zerossl.com dashboard)
CoyoteCert::with(new ZeroSSL(apiKey: 'your-api-key'))
    ->email('admin@example.com')  // required for auto-provisioning
    ->...

// Pre-provisioned credentials
CoyoteCert::with(new ZeroSSL(eabKid: 'kid', eabHmac: 'hmac'))
    ->...
```

### Google Trust Services

Obtain EAB credentials from the [Google Cloud Console](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial).

```php
use CoyoteCert\Provider\GoogleTrustServices;

CoyoteCert::with(new GoogleTrustServices(eabKid: 'kid', eabHmac: 'hmac'))
    ->...
```

### SSL.com

```php
use CoyoteCert\Provider\SslCom;

new SslCom(eabKid: 'kid', eabHmac: 'hmac')            // RSA endpoint
new SslCom(eabKid: 'kid', eabHmac: 'hmac', ecc: true) // ECC endpoint
```

### Buypass

```php
use CoyoteCert\Provider\BuypassGo;
use CoyoteCert\Provider\BuypassGoStaging;

new BuypassGo()
new BuypassGoStaging()
```

### Custom CA

```php
use CoyoteCert\Provider\CustomProvider;

new CustomProvider(
    directoryUrl: 'https://acme.example.com/directory',
    displayName:  'My CA',       // used in logs
    eabKid:       'kid',         // omit if EAB not required
    eabHmac:      'hmac',
)
```

## Challenge handlers

### http-01

```php
use CoyoteCert\Challenge\Http01Handler;

->challenge(new Http01Handler('/var/www/html'))
```

Places a token file at `{webroot}/.well-known/acme-challenge/{token}`. The web server must serve it without authentication.

### dns-01

Implement `ChallengeHandlerInterface`:

```php
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

class MyDns01Handler implements ChallengeHandlerInterface
{
    public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::DNS;
    }

    public function deploy(string $domain, string $token, string $keyAuth): void
    {
        MyDnsProvider::setTxt('_acme-challenge.' . $domain, $keyAuth);
    }

    public function cleanup(string $domain, string $token): void
    {
        MyDnsProvider::deleteTxt('_acme-challenge.' . $domain);
    }
}
```

### dns-persist-01

Like dns-01 but the TXT record persists between renewals — eliminates the DNS propagation wait on every renewal. Extend `DnsPersist01Handler` (cleanup is automatically a no-op):

```php
use CoyoteCert\Challenge\DnsPersist01Handler;

class MyDnsPersist01Handler extends DnsPersist01Handler
{
    public function deploy(string $domain, string $token, string $keyAuth): void
    {
        MyDnsProvider::setTxt('_acme-challenge.' . $domain, $keyAuth);
    }
}
```

## Storage

### Filesystem

```php
use CoyoteCert\Storage\FilesystemStorage;

->storage(new FilesystemStorage('/var/certs'))
```

Stores the account key and each certificate as JSON files in the given directory.

### In-memory

```php
use CoyoteCert\Storage\InMemoryStorage;

->storage(new InMemoryStorage())
```

Useful for testing or one-shot scripts where persistence is not needed.

### Custom

Implement `StorageInterface`:

```php
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\StorageInterface;
use CoyoteCert\Storage\StoredCertificate;

class DatabaseStorage implements StorageInterface
{
    public function hasAccountKey(): bool { ... }
    public function getAccountKey(): string { ... }
    public function getAccountKeyType(): KeyType { ... }
    public function saveAccountKey(string $pem, KeyType $type): void { ... }
    public function hasCertificate(string $domain): bool { ... }
    public function getCertificate(string $domain): ?StoredCertificate { ... }
    public function saveCertificate(string $domain, StoredCertificate $cert): void { ... }
}
```

## Issuing and renewing

### Issue (unconditional)

Always requests a fresh certificate, even if a valid one is already stored.

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->domains('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issue();
```

### Issue or renew

Returns the cached certificate if it is still valid; issues a new one otherwise. Renewal triggers when fewer than `$daysBeforeExpiry` days remain, or earlier when the CA provides an ACME Renewal Information (ARI) window.

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->domains('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew(daysBeforeExpiry: 30);
```

### Multiple domains (SAN)

```php
->domains(['example.com', 'www.example.com', 'api.example.com'])
```

## Builder reference

| Method | Default | Description |
|---|---|---|
| `::with(AcmeProviderInterface)` | — | Select the CA |
| `->storage(StorageInterface)` | none | Persist account key and certificates |
| `->email(string)` | `''` | Contact email; required for ZeroSSL auto-provisioning |
| `->domains(string\|array)` | — | Domain(s) to certify |
| `->challenge(ChallengeHandlerInterface)` | — | Challenge deployment handler |
| `->keyType(KeyType)` | `EC_P256` | Certificate key type |
| `->accountKeyType(KeyType)` | `RSA_2048` | ACME account key type |
| `->profile(string)` | `''` | ACME profile (`shortlived`, `classic`) |
| `->httpClient(ClientInterface, ...)` | curl | PSR-18 HTTP client |
| `->logger(LoggerInterface)` | none | PSR-3 logger |
| `->skipLocalTest()` | off | Skip the pre-flight HTTP/DNS self-check |

## Key types

```php
use CoyoteCert\Enums\KeyType;

->keyType(KeyType::EC_P256)   // default — fast and widely supported
->keyType(KeyType::EC_P384)
->keyType(KeyType::RSA_2048)
->keyType(KeyType::RSA_4096)
```

## ACME profiles (Let's Encrypt)

Profiles control the certificate lifetime. Let's Encrypt currently supports:

```php
->profile('shortlived') // 6-day certificate — no OCSP/CRL stapling needed
->profile('classic')    // 90-day certificate (default behaviour)
```

Profiles are silently ignored for CAs that don't support them.

## PSR-18 HTTP client

Swap out the built-in curl client for any PSR-18 implementation:

```php
// Symfony — Psr18Client implements RequestFactory + StreamFactory too
->httpClient(new \Symfony\Component\HttpClient\Psr18Client())

// Guzzle — pass a factory separately
->httpClient(
    new \GuzzleHttp\Client(),
    new \GuzzleHttp\Psr7\HttpFactory(),
)
```

## Revocation

```php
use CoyoteCert\CoyoteCert;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->revoke($storedCert);          // reason 0 — unspecified

// RFC 5280 reason codes
->revoke($storedCert, reason: 1);   // keyCompromise
->revoke($storedCert, reason: 4);   // superseded
->revoke($storedCert, reason: 5);   // cessationOfOperation
```

## Low-level API

The `Api` class gives direct access to each ACME endpoint for cases not covered by the fluent builder:

```php
use CoyoteCert\Api;
use CoyoteCert\Provider\LetsEncrypt;

$api = new Api(provider: new LetsEncrypt(), storage: $storage);

$account = $api->account()->get();
$order   = $api->order()->new($account, ['example.com']);
$window  = $api->renewalInfo()->get($cert->certificate, $issuerPem);
```

---

## Maintained by Blendbyte

<a href="https://www.blendbyte.com">
  <img src="https://avatars.githubusercontent.com/u/69378377?s=200&v=4" alt="Blendbyte" width="80" align="left" style="margin-right: 16px;">
</a>

This project is maintained by **[Blendbyte](https://www.blendbyte.com)** — a team of engineers with 20+ years of experience building cloud infrastructure, web applications, and developer tools. We use these packages in production ourselves and actively contribute to the open source ecosystem we rely on every day. Issues and PRs are always welcome.

🌐 [blendbyte.com](https://www.blendbyte.com) · 📧 [hello@blendbyte.com](mailto:hello@blendbyte.com)

<br clear="left">
