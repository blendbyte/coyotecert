# CoyoteCert

[![Latest Version on Packagist](https://img.shields.io/packagist/v/blendbyte/coyotecert.svg?style=flat-square)](https://packagist.org/packages/blendbyte/coyotecert)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://github.com/blendbyte/coyotecert/blob/main/LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-787cb5?style=flat-square)](https://www.php.net)
[![Tests](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/tests.yml?branch=main&style=flat-square&label=tests)](https://github.com/blendbyte/coyotecert/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/codecov/c/github/blendbyte/coyotecert?style=flat-square)](https://codecov.io/gh/blendbyte/coyotecert)

**A modern, fully RFC 8555-compliant ACME v2 client for PHP 8.3+.** Issue, renew, and revoke TLS certificates from Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, Buypass, or any standards-compliant CA — with a clean fluent API, zero framework dependencies, and production-grade test coverage.

ACME (Automatic Certificate Management Environment) is the protocol that powers free, automated TLS certificates. CoyoteCert speaks the full protocol: account management, order lifecycle, HTTP-01 and DNS-01 challenge validation, certificate issuance, ARI-based smart renewal, and revocation. Everything you need from a single `composer require`.

---

## Why CoyoteCert

### Full RFC 8555 + RFC 9773 compliance

CoyoteCert implements the complete ACME v2 specification — not just the happy path. That means proper nonce handling with automatic retry on `badNonce`, JWS signing for every request, EAB for CAs that require it, and ARI (Automatic Renewal Information, RFC 9773) for CA-guided renewal windows. If the CA publishes an ARI endpoint, CoyoteCert will respect it instead of guessing based on days remaining.

### ECDSA-first key management

Account keys and certificate keys both default to EC P-256 — the algorithm recommended by modern CAs for its speed and small key sizes. EC P-384, RSA-2048, and RSA-4096 are also available. JWS tokens are signed with the correct algorithm for each key type (ES256, ES384, RS256), so requests are accepted first time even by strict CAs.

### Works with every major CA out of the box

Built-in providers for Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, and Buypass — including full EAB support. ZeroSSL auto-provisions its EAB credentials from an API key so you never have to copy-paste tokens. A `CustomProvider` covers any ACME-compliant CA you might need.

### dns-persist-01: renewals without DNS propagation delays

CoyoteCert introduces `dns-persist-01`, a challenge strategy where the TXT record is deployed once and kept in place between renewals. When it is time to renew, the CA validates immediately against the existing record — no waiting for DNS propagation on every 90-day cycle.

### ACME profiles and short-lived certificates

Let's Encrypt's `shortlived` profile issues 6-day certificates that never need OCSP stapling or CRL distribution. CoyoteCert passes the profile to the order, and silently skips it for CAs that don't support profiles.

### Swappable HTTP client (PSR-18)

The built-in curl client requires no dependencies. When you need proxy support, custom middleware, or framework integration, swap it for any PSR-18 client — Symfony HttpClient, Guzzle, or anything else — with one builder call.

### Three storage backends, fully swappable

Filesystem with file locking, PDO (MySQL, PostgreSQL, SQLite) with dialect-aware upserts, and in-memory for testing. All three implement the same interface, so switching never touches your issuance code.

### Pre-flight self-test

Before asking the CA to validate a domain, CoyoteCert performs a local check — fetches the HTTP challenge token or looks up the DNS TXT record itself. Misconfigured web servers and DNS propagation delays are caught before they waste a rate-limit attempt.

### 93 %+ test coverage with real CA integration tests

Every code path is unit-tested with mocked responses. The integration suite runs against a live [Pebble](https://github.com/letsencrypt/pebble) ACME test server in CI across PHP 8.3, 8.4, and 8.5. No mock-only false confidence.

### Modern, idiomatic PHP

PHP 8.3+, strict types, backed enums, readonly constructor promotion, named arguments throughout. No magic methods, no global state, no hidden singletons.

---

## Requirements

- PHP ^8.3
- `ext-curl`, `ext-json`, `ext-mbstring`, `ext-openssl`

---

## Installation

```bash
composer require blendbyte/coyotecert
```

---

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
    ->issueOrRenew();

// Use the certificate
echo $cert->certificate; // PEM leaf certificate
echo $cert->privateKey;  // PEM private key
echo $cert->fullchain;   // PEM leaf + intermediates
echo $cert->caBundle;    // PEM intermediate chain
```

---

## Table of contents

- [Providers](#providers)
- [Challenge handlers](#challenge-handlers)
- [Storage backends](#storage-backends)
- [Issuing certificates](#issuing-certificates)
- [Wildcard and multi-domain certificates](#wildcard-and-multi-domain-certificates)
- [Automatic renewal](#automatic-renewal)
- [ARI — CA-guided renewal windows](#ari--ca-guided-renewal-windows)
- [ACME profiles](#acme-profiles)
- [Key types](#key-types)
- [Certificate revocation](#certificate-revocation)
- [PSR-18 HTTP client](#psr-18-http-client)
- [HTTP timeout](#http-timeout)
- [Logging](#logging)
- [Inspecting StoredCertificate](#inspecting-storedcertificate)
- [Builder reference](#builder-reference)
- [Low-level API](#low-level-api)
- [Testing with Pebble](#testing-with-pebble)

---

## Providers

CoyoteCert ships with built-in providers for every major public ACME CA.

| Provider class | CA | EAB | Profiles |
|---|---|---|---|
| `LetsEncrypt` | Let's Encrypt (production) | No | Yes |
| `LetsEncryptStaging` | Let's Encrypt (staging) | No | Yes |
| `ZeroSSL` | ZeroSSL | Yes | No |
| `BuypassGo` | Buypass Go SSL (production) | No | No |
| `BuypassGoStaging` | Buypass Go SSL (staging) | No | No |
| `GoogleTrustServices` | Google Trust Services | Yes | No |
| `SslCom` | SSL.com | Yes | No |
| `CustomProvider` | Any RFC 8555-compliant CA | Optional | Optional |

### Let's Encrypt

```php
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;

// Production — issues browser-trusted certificates
CoyoteCert::with(new LetsEncrypt())

// Staging — rate-limit-free, not browser-trusted; use during development
CoyoteCert::with(new LetsEncryptStaging())
```

### ZeroSSL

ZeroSSL requires EAB credentials. CoyoteCert can provision them automatically from your API key, or you can supply pre-provisioned credentials directly.

```php
use CoyoteCert\Provider\ZeroSSL;

// Automatic provisioning — CoyoteCert fetches EAB credentials from the ZeroSSL API
CoyoteCert::with(new ZeroSSL(apiKey: 'your-zerossl-api-key'))
    ->email('admin@example.com') // required for auto-provisioning

// Manual credentials — skip the API call
CoyoteCert::with(new ZeroSSL(eabKid: 'kid', eabHmac: 'hmac'))
```

### Google Trust Services

Obtain EAB credentials from the [Google Cloud Console](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial).

```php
use CoyoteCert\Provider\GoogleTrustServices;

CoyoteCert::with(new GoogleTrustServices(eabKid: 'kid', eabHmac: 'hmac'))
```

### SSL.com

SSL.com exposes separate endpoints for RSA and ECC certificates.

```php
use CoyoteCert\Provider\SslCom;

// RSA endpoint (default)
CoyoteCert::with(new SslCom(eabKid: 'kid', eabHmac: 'hmac'))

// ECC endpoint
CoyoteCert::with(new SslCom(eabKid: 'kid', eabHmac: 'hmac', ecc: true))
```

### Buypass Go SSL

```php
use CoyoteCert\Provider\BuypassGo;
use CoyoteCert\Provider\BuypassGoStaging;

CoyoteCert::with(new BuypassGo())
CoyoteCert::with(new BuypassGoStaging()) // staging, no rate limits
```

### Custom CA

Point CoyoteCert at any ACME-compliant directory URL.

```php
use CoyoteCert\Provider\CustomProvider;

CoyoteCert::with(new CustomProvider(
    directoryUrl:      'https://acme.example.com/directory',
    displayName:       'My Internal CA',  // used in log messages
    eabKid:            'kid',             // omit if EAB not required
    eabHmac:           'hmac',
    verifyTls:         true,
    profilesSupported: false,
))
```

---

## Challenge handlers

ACME requires you to prove domain ownership by completing a challenge. CoyoteCert ships with an HTTP-01 handler and an abstract base for DNS-persist-01. DNS-01 is implemented via the `ChallengeHandlerInterface`.

### http-01

The simplest challenge type. CoyoteCert writes a token file to your web root; the CA fetches it over HTTP.

```php
use CoyoteCert\Challenge\Http01Handler;

->challenge(new Http01Handler('/var/www/html'))
```

The file is written to `{webroot}/.well-known/acme-challenge/{token}` and removed automatically after validation. Your web server must serve it as plain text without authentication.

### dns-01

Deploy a TXT record at `_acme-challenge.{domain}` and remove it after validation. Implement `ChallengeHandlerInterface`:

```php
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

class CloudflareDns01Handler implements ChallengeHandlerInterface
{
    public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::DNS;
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        // $keyAuthorization is the value to put in the TXT record
        Cloudflare::setTxtRecord('_acme-challenge.' . $domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        Cloudflare::deleteTxtRecord('_acme-challenge.' . $domain);
    }
}
```

```php
->challenge(new CloudflareDns01Handler())
```

DNS-01 is the only challenge type that supports wildcard certificates (`*.example.com`).

### dns-persist-01

A CoyoteCert-specific strategy where the TXT record is deployed once and kept in place permanently. On every subsequent renewal, the CA validates against the same record — no DNS propagation wait, no deploy/cleanup cycle.

Extend `DnsPersist01Handler` and implement `deploy()`. The `cleanup()` method is a final no-op.

```php
use CoyoteCert\Challenge\DnsPersist01Handler;

class Route53DnsPersist01Handler extends DnsPersist01Handler
{
    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        // Called on first issuance; key auth changes on each renewal,
        // so you must update the record even if it already exists.
        Route53::upsertTxtRecord('_acme-challenge.' . $domain, $keyAuthorization);
    }
}
```

```php
->challenge(new Route53DnsPersist01Handler())
```

> **Note:** The TXT record value (`$keyAuthorization`) changes on every order, even with dns-persist-01. Your `deploy()` must update (upsert) the record, not skip it if it already exists.

---

## Storage backends

Storage persists the ACME account key and issued certificates between runs. Without storage, CoyoteCert issues fresh certificates every time and creates a new ACME account on each request.

### Filesystem

```php
use CoyoteCert\Storage\FilesystemStorage;

->storage(new FilesystemStorage('/var/certs'))
```

Files written:

| File | Contents |
|---|---|
| `/var/certs/account.pem` | ACME account private key (mode 0600) |
| `/var/certs/account.json` | Key type metadata |
| `/var/certs/{domain}.cert.json` | Serialised `StoredCertificate` |

The directory is created automatically (mode 0700). Reads use shared locks; writes use exclusive locks — safe for concurrent processes.

### Database (PDO)

Store everything in a single key-value table. Supports MySQL/MariaDB, PostgreSQL, and SQLite out of the box.

```php
use CoyoteCert\Storage\DatabaseStorage;

$pdo     = new PDO('mysql:host=localhost;dbname=myapp', $user, $pass);
$storage = new DatabaseStorage($pdo);

// Or with a custom table name
$storage = new DatabaseStorage($pdo, table: 'ssl_storage');
```

Run this once to create the table:

```php
$pdo->exec(DatabaseStorage::createTableSql());
// Or with a custom name:
$pdo->exec(DatabaseStorage::createTableSql('ssl_storage'));
```

The generated schema (MySQL):

```sql
CREATE TABLE IF NOT EXISTS `coyote_cert_storage` (
    `id`         INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `store_key`  VARCHAR(255)  NOT NULL,
    `value`      MEDIUMTEXT    NOT NULL,
    `updated_at` TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_store_key` (`store_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Upserts are dialect-aware: `INSERT OR REPLACE` (SQLite), `ON CONFLICT DO UPDATE` (PostgreSQL), `ON DUPLICATE KEY UPDATE` (MySQL/MariaDB).

### In-memory

Non-persistent; data is lost when the process exits. Useful in tests and one-shot scripts.

```php
use CoyoteCert\Storage\InMemoryStorage;

->storage(new InMemoryStorage())
```

### Custom storage

Implement `StorageInterface` with seven methods:

```php
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\StorageInterface;
use CoyoteCert\Storage\StoredCertificate;

class RedisStorage implements StorageInterface
{
    public function __construct(private \Redis $redis) {}

    public function hasAccountKey(): bool
    {
        return (bool) $this->redis->exists('acme:account:pem');
    }

    public function getAccountKey(): string
    {
        return $this->redis->get('acme:account:pem');
    }

    public function getAccountKeyType(): KeyType
    {
        return KeyType::from($this->redis->get('acme:account:type'));
    }

    public function saveAccountKey(string $pem, KeyType $type): void
    {
        $this->redis->set('acme:account:pem', $pem);
        $this->redis->set('acme:account:type', $type->value);
    }

    public function hasCertificate(string $domain): bool
    {
        return (bool) $this->redis->exists("acme:cert:{$domain}");
    }

    public function getCertificate(string $domain): ?StoredCertificate
    {
        $json = $this->redis->get("acme:cert:{$domain}");
        return $json ? StoredCertificate::fromArray(json_decode($json, true)) : null;
    }

    public function saveCertificate(string $domain, StoredCertificate $cert): void
    {
        $this->redis->set("acme:cert:{$domain}", json_encode($cert->toArray()));
    }
}
```

---

## Issuing certificates

### issue()

Always requests a new certificate from the CA, regardless of what is in storage.

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->domains('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issue();
```

### issueOrRenew()

The recommended method for production. Returns the existing certificate if it is still valid; issues a new one otherwise. Accepts an optional `$daysBeforeExpiry` threshold (default 30).

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->domains('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew(daysBeforeExpiry: 30);
```

Run this in a cron job or scheduler. It is safe to call as often as you like — it does nothing when the certificate is still valid.

### renew()

Alias for `issue()`. Forces a fresh certificate regardless of expiry.

```php
$cert = $coyote->renew();
```

### needsRenewal()

Check whether a renewal is needed without triggering one.

```php
$coyote = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->domains('example.com');

if ($coyote->needsRenewal(30)) {
    // issue or alert
}
```

Returns `true` when:
- No storage is configured
- No certificate is stored for the primary domain
- The stored certificate expires within `$daysBeforeExpiry` days
- An ARI renewal window is open (see [ARI](#ari--ca-guided-renewal-windows))

---

## Wildcard and multi-domain certificates

Pass an array of domains to `->domains()`. Wildcards require DNS-01 or dns-persist-01.

```php
// Multi-domain (SAN) certificate via HTTP-01
CoyoteCert::with(new LetsEncrypt())
    ->domains(['example.com', 'www.example.com', 'api.example.com'])
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew();

// Wildcard certificate via DNS-01
CoyoteCert::with(new LetsEncrypt())
    ->domains(['example.com', '*.example.com'])
    ->challenge(new CloudflareDns01Handler())
    ->issueOrRenew();
```

`*.example.com` covers one label deep (`sub.example.com`) but not the apex (`example.com`). Include both if you need both.

---

## Automatic renewal

The recommended deployment pattern is a scheduled cron job calling `issueOrRenew()`:

```php
// /usr/local/bin/renew-certs.php

require __DIR__ . '/vendor/autoload.php';

use CoyoteCert\CoyoteCert;
use CoyoteCert\Challenge\Http01Handler;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('certs');
$logger->pushHandler(new StreamHandler('/var/log/certs.log'));

$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->email('ops@example.com')
    ->domains(['example.com', 'www.example.com'])
    ->challenge(new Http01Handler('/var/www/html'))
    ->logger($logger)
    ->issueOrRenew(daysBeforeExpiry: 30);

// Reload web server only if a new certificate was issued
// (compare serial or expiry to detect renewal)
```

Add to crontab — daily is sufficient; `issueOrRenew()` skips the CA call when nothing is due:

```
0 3 * * * php /usr/local/bin/renew-certs.php
```

---

## ARI — CA-guided renewal windows

[RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) lets a CA advertise a specific time window during which it wants you to renew. CoyoteCert checks the ARI endpoint automatically when `needsRenewal()` or `issueOrRenew()` is called.

- If the CA exposes a `renewalInfo` URL in its directory and the renewal window is currently open, `needsRenewal()` returns `true` even if the certificate has more than `$daysBeforeExpiry` days remaining.
- If the ARI request fails (network error, non-200 response), CoyoteCert falls back to the `$daysBeforeExpiry` threshold silently.
- If the CA does not support ARI (no `renewalInfo` in the directory), the threshold is used exclusively.

No configuration is required. CoyoteCert handles this transparently.

---

## ACME profiles

Profiles let you request a specific certificate type from the CA. Let's Encrypt currently supports two:

```php
->profile('shortlived') // 6-day certificate — no OCSP/CRL infrastructure needed
->profile('classic')    // 90-day certificate (default if no profile specified)
```

Short-lived certificates are renewed more frequently but eliminate the need for OCSP stapling, CRL checks, and revocation infrastructure — a significant operational simplification.

Profiles are forwarded to the CA only if the provider reports `supportsProfiles() === true`. For CAs that don't support profiles (ZeroSSL, Buypass, etc.) the setting is silently ignored, so you can call `->profile()` unconditionally.

---

## Key types

```php
use CoyoteCert\Enums\KeyType;

// Certificate key type (default: EC_P256)
->keyType(KeyType::EC_P256)   // ECDSA P-256 — fast, compact, widely supported
->keyType(KeyType::EC_P384)   // ECDSA P-384 — higher security margin
->keyType(KeyType::RSA_2048)  // RSA 2048-bit
->keyType(KeyType::RSA_4096)  // RSA 4096-bit — maximum compatibility

// ACME account key type (default: EC_P256)
->accountKeyType(KeyType::RSA_2048)
```

EC P-256 is the default for both the certificate and the account key. It produces smaller keys and faster TLS handshakes than RSA while being accepted by all major CAs and browsers.

---

## Certificate revocation

Revoke a stored certificate with an optional RFC 5280 reason code.

```php
use CoyoteCert\CoyoteCert;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

$coyote = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'));

$cert = $coyote->storage->getCertificate('example.com');

$coyote->revoke($cert);               // reason 0 — unspecified (default)
$coyote->revoke($cert, reason: 1);    // keyCompromise
$coyote->revoke($cert, reason: 2);    // cACompromise
$coyote->revoke($cert, reason: 3);    // affiliationChanged
$coyote->revoke($cert, reason: 4);    // superseded
$coyote->revoke($cert, reason: 5);    // cessationOfOperation
```

Returns `true` on success, `false` if the CA rejected the request.

---

## PSR-18 HTTP client

CoyoteCert ships with a built-in curl client that requires no extra dependencies. To use a custom HTTP client, pass any PSR-18 `ClientInterface`:

```php
// Symfony HttpClient — implements all three interfaces itself
->httpClient(new \Symfony\Component\HttpClient\Psr18Client())

// Guzzle — pass request and stream factories separately
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;

->httpClient(
    new Client(),
    new HttpFactory(), // RequestFactoryInterface
    new HttpFactory(), // StreamFactoryInterface — same object works for both
)

// Nyholm PSR-7 + any client
use Nyholm\Psr7\Factory\Psr17Factory;

$factory = new Psr17Factory();
->httpClient($myClient, $factory, $factory)
```

If the PSR-18 client also implements `RequestFactoryInterface` and `StreamFactoryInterface`, the factory arguments are optional and detected automatically.

---

## HTTP timeout

Adjust the built-in curl client's timeout without replacing the whole client:

```php
->withHttpTimeout(30) // seconds
```

If a custom PSR-18 client is configured, this call has no effect — configure the timeout in your client directly.

---

## Logging

Pass any PSR-3 logger to receive debug and info messages during the certificate lifecycle:

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('acme');
$logger->pushHandler(new StreamHandler('php://stdout'));

CoyoteCert::with(new LetsEncrypt())
    ->logger($logger)
    ->...
```

Log messages cover directory fetches, nonce acquisition, challenge deployment, validation polling, and order finalisation. Nothing is logged when no logger is configured.

---

## Inspecting StoredCertificate

`StoredCertificate` is the value object returned by `issue()`, `issueOrRenew()`, and `renew()`. It holds all certificate data and exposes inspection helpers.

### Properties

```php
$cert->certificate  // string — PEM leaf certificate
$cert->privateKey   // string — PEM private key
$cert->fullchain    // string — PEM leaf + intermediate chain
$cert->caBundle     // string — PEM intermediate chain only
$cert->issuedAt     // DateTimeImmutable
$cert->expiresAt    // DateTimeImmutable
$cert->domains      // string[] — domains as recorded at issuance time
```

### Methods

```php
// Days until expiry — 0 if already expired
$cert->remainingDays();

// Ceiling of days until expiry — negative if expired
$cert->daysUntilExpiry();

// Whether the certificate covers all the given domains (wildcard-aware)
$cert->isValidForDomains(['example.com', 'www.example.com']); // bool

// DNS SANs from the actual certificate
$cert->sans(); // ['example.com', 'www.example.com']

// Lowercase hex serial number
$cert->serialNumber(); // 'a1b2c3...'

// Authority Key Identifier (colon-separated uppercase hex, or null if absent)
$cert->authorityKeyId(); // 'A1:B2:C3:...'

// Issuer DN fields
$cert->issuer(); // ['CN' => "Let's Encrypt R11", 'O' => "Let's Encrypt", 'C' => 'US']
```

### Serialisation

`StoredCertificate` round-trips through JSON cleanly:

```php
$array = $cert->toArray();
$cert  = StoredCertificate::fromArray($array);
```

---

## Builder reference

```php
CoyoteCert::with(AcmeProviderInterface $provider)  // factory — select the CA
```

| Method | Type | Default | Description |
|---|---|---|---|
| `->email(string)` | fluent | `''` | Contact email; required for ZeroSSL auto-provisioning |
| `->domains(string\|array)` | fluent | — | Domain(s) to certify; first entry is the primary |
| `->challenge(ChallengeHandlerInterface)` | fluent | — | Challenge handler |
| `->storage(StorageInterface)` | fluent | none | Storage backend |
| `->keyType(KeyType)` | fluent | `EC_P256` | Certificate key algorithm |
| `->accountKeyType(KeyType)` | fluent | `EC_P256` | ACME account key algorithm |
| `->profile(string)` | fluent | `''` | ACME profile (`shortlived`, `classic`) |
| `->httpClient(ClientInterface, ...)` | fluent | built-in curl | PSR-18 HTTP client |
| `->withHttpTimeout(int)` | fluent | `10` | Curl timeout in seconds |
| `->logger(LoggerInterface)` | fluent | none | PSR-3 logger |
| `->skipLocalTest()` | fluent | off | Disable pre-flight HTTP/DNS self-check |
| `->issue()` | terminal | — | Issue unconditionally; returns `StoredCertificate` |
| `->renew()` | terminal | — | Alias for `issue()` |
| `->issueOrRenew(int $days = 30)` | terminal | — | Issue only when needed; returns `StoredCertificate` |
| `->needsRenewal(int $days = 30)` | query | — | `true` if renewal is needed |
| `->revoke(StoredCertificate, int $reason = 0)` | terminal | — | Revoke a certificate |

---

## Low-level API

For advanced use cases — custom account management, manual order orchestration, or scripted key rollovers — the `Api` class exposes every ACME endpoint directly.

```php
use CoyoteCert\Api;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

$api = new Api(
    provider: new LetsEncrypt(),
    storage:  new FilesystemStorage('/var/certs'),
);

// Account management
$account = $api->account()->create('admin@example.com');
$account = $api->account()->get();
$account = $api->account()->update($account, ['mailto:new@example.com']);
$account = $api->account()->deactivate($account);
$account = $api->account()->keyRollover($account);  // rotate account key in place

// Order lifecycle
$order = $api->order()->new($account, ['example.com', 'www.example.com']);
$order = $api->order()->refresh($order);
$order = $api->order()->waitUntilValid($order);
$order = $api->order()->finalize($order, $csrPem);

// Domain validation
$statuses = $api->domainValidation()->status($order);
$data     = $api->domainValidation()->getValidationData($statuses, $challengeType);
$api->domainValidation()->start($account, $status, $challengeType, localTest: true);
$api->domainValidation()->allChallengesPassed($order); // polls with retry

// Certificate
$bundle = $api->certificate()->getBundle($order);
$api->certificate()->revoke($certPem, reason: 1);

// ARI
$window = $api->renewalInfo()->get($certPem, $issuerPem);
$certId = $api->renewalInfo()->certId($certPem, $issuerPem);

// Directory
$all    = $api->directory()->all();
$newAcc = $api->directory()->newAccount();
$ariUrl = $api->directory()->renewalInfo(); // null if not supported
```

---

## Testing with Pebble

[Pebble](https://github.com/letsencrypt/pebble) is a small, RFC-compliant ACME test server from the Let's Encrypt team. Use it to run end-to-end tests without hitting real CA rate limits.

```php
use CoyoteCert\Provider\Pebble;

// Default — connects to localhost:14000 with TLS verification disabled
CoyoteCert::with(new Pebble())

// Custom URL
CoyoteCert::with(new Pebble(url: 'https://pebble.internal:14000/dir'))

// With EAB (if Pebble is configured for it)
CoyoteCert::with(new Pebble(eab: true, eabKid: 'kid', eabHmac: 'hmac'))
```

Docker Compose example for local development:

```yaml
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    ports:
      - "14000:14000"
      - "15000:15000"
    environment:
      PEBBLE_VA_NOSLEEP: "1"
      PEBBLE_VA_ALWAYS_VALID: "1"
```

---

## Maintained by Blendbyte

<a href="https://www.blendbyte.com">
  <img src="https://avatars.githubusercontent.com/u/69378377?s=200&v=4" alt="Blendbyte" width="80" align="left" style="margin-right: 16px;">
</a>

This project is maintained by **[Blendbyte](https://www.blendbyte.com)** — a team of engineers with 20+ years of experience building cloud infrastructure, web applications, and developer tools. We use these packages in production ourselves and actively contribute to the open source ecosystem we rely on every day. Issues and PRs are always welcome.

🌐 [blendbyte.com](https://www.blendbyte.com) · 📧 [hello@blendbyte.com](mailto:hello@blendbyte.com)

<br clear="left">
