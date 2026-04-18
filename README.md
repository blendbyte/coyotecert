<img width="2560" height="1706" alt="coyotecert-banner-2560x1706" src="https://github.com/user-attachments/assets/d5510075-b62c-462f-a941-1d31b48bbec3" />

# CoyoteCert

[![Latest Version on Packagist](https://img.shields.io/packagist/v/blendbyte/coyotecert.svg?style=flat-square)](https://packagist.org/packages/blendbyte/coyotecert)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://github.com/blendbyte/coyotecert/blob/main/LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-787cb5?style=flat-square)](https://www.php.net)
[![Tests](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/tests.yml?branch=main&style=flat-square&label=tests)](https://github.com/blendbyte/coyotecert/actions/workflows/tests.yml)
[![Static Analysis](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/static-analysis.yml?branch=main&style=flat-square&label=phpstan)](https://github.com/blendbyte/coyotecert/actions/workflows/static-analysis.yml)
[![Coverage](https://img.shields.io/codecov/c/github/blendbyte/coyotecert?style=flat-square)](https://codecov.io/gh/blendbyte/coyotecert)

**A PHP 8.3+ ACME v2 client for issuing, renewing, and revoking TLS certificates.** Works with Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, Buypass, and any RFC 8555-compliant CA. Fluent API, no framework dependencies, and solid test coverage.

ACME (Automatic Certificate Management Environment) is the protocol behind free, automated TLS certificates. Yes, same name as the cartoon supply company. CoyoteCert covers the full thing: account management, order lifecycle, HTTP-01, DNS-01, and TLS-ALPN-01 challenges, certificate issuance, smart renewal with ARI, and revocation. One `composer require` and you're set.

---

## Why CoyoteCert

### Works with every major CA out of the box

Built-in providers for Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, and Buypass, with full EAB support. ZeroSSL auto-provisions EAB credentials from your API key, so no copy-pasting tokens. A `CustomProvider` handles any other ACME-compliant CA.

### CLI included

`coyote issue` and `coyote status` ship in the same package. One command to issue or renew a certificate; a second to inspect what's stored. Works as a drop-in for certbot and acme.sh in PHP stacks, with full support for every built-in provider, key type, and storage path — and a cron-friendly exit code so renewals fit into any deployment pipeline.

### Three storage backends, fully swappable

Filesystem with file locking, PDO (MySQL, PostgreSQL, SQLite), and in-memory for testing. All three share the same interface, so switching backends doesn't touch your issuance code.

### Six built-in DNS-01 providers

Cloudflare, Hetzner DNS, DigitalOcean, ClouDNS, AWS Route53, and shell/exec — all with automatic zone detection, post-deploy propagation checking, and a fluent builder for timeout and delay tuning. No AWS SDK required for Route53. Pass `--dns cloudflare` in the CLI or hand a handler directly to `->challenge()`. Wildcard certificates require DNS-01; CoyoteCert has the providers covered out of the box.

### dns-persist-01: renewals without DNS propagation delays

CoyoteCert introduces `dns-persist-01`: deploy the TXT record once, leave it in place, and every subsequent renewal validates against it immediately. No DNS propagation wait on every 90-day cycle.

### Fails fast, before it costs you

Before submitting an order, CoyoteCert checks CAA DNS records for every domain. If a record blocks the chosen CA, you get an immediate `CaaException` naming the domain. It also does a pre-flight fetch of the HTTP token or DNS TXT record before asking the CA to validate. Misconfigured servers and propagation delays are caught locally. No wasted rate-limit attempts, no surprise failures.

### Typed exceptions for every failure mode

`RateLimitException` carries the CA's `Retry-After` seconds so your retry logic is precise. `AuthException` means bad credentials, not a transient error. `AcmeException::getSubproblems()` tells you exactly which domain in a multi-domain order was rejected and why.

### ACME profiles and short-lived certificates

Let's Encrypt's `shortlived` profile issues 6-day certificates with no OCSP or CRL requirements. CoyoteCert passes the profile through and silently ignores it for CAs that don't support it yet.

### Full RFC 8555 + RFC 9773 compliance

Proper nonce handling with automatic retry on `badNonce`, JWS signing for every request, EAB for CAs that require it, and ARI (RFC 9773) so renewal windows are guided by the CA rather than a fixed day count.

### CA-independent: no hidden defaults

CoyoteCert has no default CA. Every issuance call requires you to pass a provider explicitly. Choosing a CA involves real trade-offs (trust store coverage, rate limits, certificate lifetime, EAB requirements, data residency) and that decision belongs to you, not the library.

### Also

- **ECDSA-first**: keys default to EC P-256; EC P-384, RSA-2048, and RSA-4096 are also supported.
- **IP address certificates** (RFC 8738): pass an IP to `->identifiers()` and it just works. `type: ip` on the order, `IP:` SANs in the CSR.
- **PSR-18 HTTP client**: the built-in curl client needs no extra dependencies; swap it for any PSR-18 client with one builder call.
- **94%+ test coverage**: unit tests with mocked responses plus a live [Pebble](https://github.com/letsencrypt/pebble) integration suite across PHP 8.3, 8.4, and 8.5. No mock-only false confidence.
- **Modern PHP**: strict types, backed enums, readonly constructor promotion. No magic methods, no global state.
- **Truly independent**: no CA affiliation, not maintained or financed by one.

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
    ->identifiers('example.com')
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

## CLI

CoyoteCert ships with a `coyote` CLI for issuing and inspecting certificates without writing PHP. It wraps the same builder API as the library.

### Install globally

```bash
composer global require blendbyte/coyotecert
```

Make sure `~/.composer/vendor/bin` (or `~/.config/composer/vendor/bin` on Linux) is on your `PATH`.

### `coyote issue`

Issue or renew a certificate using HTTP-01 or DNS-01 challenge validation.

**HTTP-01** — write a token file to your web root:

```bash
coyote issue \
  --domain example.com \
  --domain www.example.com \
  --webroot /var/www/html \
  --email admin@example.com \
  --provider letsencrypt \
  --storage /etc/certs
```

**DNS-01** — create a TXT record via a DNS provider (required for wildcards). Set the provider's credentials as environment variables, then pass `--dns`:

```bash
export CLOUDFLARE_API_TOKEN=your-token

coyote issue \
  --domain example.com \
  --domain '*.example.com' \
  --dns cloudflare \
  --email admin@example.com \
  --provider letsencrypt \
  --storage /etc/certs
```

If a valid certificate already exists and expiry is more than `--days` away, the command exits cleanly with no network requests. Pass `--force` to issue regardless.

**Options**

| Option | Short | Default | Description |
|---|---|---|---|
| `--domain` | `-d` | — | Domain to include on the certificate. Repeat for SANs: `--domain example.com --domain www.example.com` |
| `--email` | `-e` | — | Contact email registered with the ACME account |
| `--webroot` | `-w` | — | Webroot path for HTTP-01. CoyoteCert writes tokens under `.well-known/acme-challenge/` |
| `--dns` | — | — | DNS provider for DNS-01 challenge. See DNS providers table below. Mutually exclusive with `--webroot` |
| `--dns-propagation-timeout` | — | `60` | Seconds to wait for the TXT record to appear in DNS before submitting the challenge to the CA |
| `--dns-propagation-delay` | — | `0` | Fixed delay in seconds after the propagation check, for providers with slow secondary sync |
| `--dns-skip-propagation` | — | — | Skip the post-deploy DNS propagation check entirely (split-horizon or internal DNS) |
| `--provider` | `-p` | — | CA to use. See provider table below. **Required** |
| `--storage` | `-s` | `./certs` | Directory to read/write certificates and account keys |
| `--days` | — | `30` | Renew when fewer than this many days remain before expiry |
| `--key-type` | — | `ec256` | Certificate key type: `ec256`, `ec384`, `rsa2048`, `rsa4096` |
| `--force` | `-f` | — | Issue a fresh certificate even if the current one is still valid |
| `--skip-caa` | — | — | Skip CAA DNS pre-check |
| `--skip-local-test` | — | — | Skip the HTTP pre-flight self-test |
| `--zerossl-key` | — | — | ZeroSSL API key for automatic EAB provisioning |
| `--eab-kid` | — | — | EAB key ID (Google Trust Services, SSL.com, or pre-provisioned ZeroSSL) |
| `--eab-hmac` | — | — | EAB HMAC key |

**Providers**

| `--provider` value | CA |
|---|---|
| `letsencrypt`, `le` | Let's Encrypt (production) |
| `letsencrypt-staging`, `le-staging`, `staging` | Let's Encrypt (staging) |
| `zerossl` | ZeroSSL (use `--zerossl-key` or `--eab-kid`/`--eab-hmac`) |
| `google`, `gts` | Google Trust Services (requires `--eab-kid` and `--eab-hmac`) |
| `buypass` | Buypass Go SSL (production) |
| `buypass-staging` | Buypass Go SSL (staging) |
| `sslcom`, `ssl.com` | SSL.com (requires `--eab-kid` and `--eab-hmac`) |

**DNS providers**

| `--dns` value | Required env vars | Optional zone override |
|---|---|---|
| `cloudflare` | `CLOUDFLARE_API_TOKEN` | `CLOUDFLARE_ZONE_ID` |
| `hetzner` | `HETZNER_API_TOKEN` | `HETZNER_ZONE_ID` |
| `digitalocean`, `do` | `DO_API_TOKEN` | `DO_ZONE` |
| `cloudns` | `CLOUDNS_AUTH_ID`, `CLOUDNS_AUTH_PASSWORD` | `CLOUDNS_ZONE` |
| `route53` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | `AWS_ROUTE53_ZONE_ID` |
| `exec`, `shell` | `DNS_DEPLOY_CMD` | `DNS_CLEANUP_CMD` |

Zone is auto-detected from the domain for all providers that support it. Supply the zone override to skip the detection API call or to disambiguate when the same domain appears in multiple zones.

### `coyote status`

Inspect a stored certificate.

```bash
coyote status --domain example.com --storage /etc/certs
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--domain` | `-d` | — | Primary domain of the certificate to inspect |
| `--storage` | `-s` | `./certs` | Directory where certificates are stored |
| `--key-type` | — | `ec256` | Key type to look up: `ec256`, `ec384`, `rsa2048`, `rsa4096` |

The status line reflects time to expiry:

| Status | Condition |
|---|---|
| `Valid` | More than 30 days remaining |
| `Renewal due` | 7–30 days remaining |
| `Expiring soon` | Fewer than 7 days remaining |
| `Expired` | Certificate has passed its expiry date |

### Cron renewal

Add a daily cron job to keep certificates renewed automatically:

```
0 3 * * * coyote issue --domain example.com --webroot /var/www/html --storage /etc/certs --email admin@example.com
```

The command is idempotent — it does nothing until fewer than `--days` (default 30) remain, so running it daily is safe.

### Help and version

```bash
coyote --help     # List available commands
coyote --version  # Show version
coyote issue --help   # Full option reference for the issue command
coyote status --help  # Full option reference for the status command
```

---

## Table of contents

- [CLI](#cli)
- [Providers](#providers)
- [Challenge handlers](#challenge-handlers)
- [DNS-01 providers](#dns-01-providers)
- [Storage backends](#storage-backends)
- [Issuing certificates](#issuing-certificates)
- [Event callbacks](#event-callbacks)
- [CAA pre-check](#caa-pre-check)
- [Wildcard and multi-domain certificates](#wildcard-and-multi-domain-certificates)
- [IP address certificates](#ip-address-certificates-rfc-8738)
- [Automatic renewal](#automatic-renewal)
- [ARI: CA-guided renewal windows](#ari-ca-guided-renewal-windows)
- [ACME profiles](#acme-profiles)
- [Preferred chain selection](#preferred-chain-selection)
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

| Provider class | CA | EAB | Profiles | CAA identifier |
|---|---|---|---|---|
| `LetsEncrypt` | Let's Encrypt (production) | No | Yes | `letsencrypt.org` |
| `LetsEncryptStaging` | Let's Encrypt (staging) | No | Yes | `letsencrypt.org` |
| `ZeroSSL` | ZeroSSL | Yes | No | `sectigo.com`, `comodoca.com` |
| `BuypassGo` | Buypass Go SSL (production) | No | No | `buypass.com` |
| `BuypassGoStaging` | Buypass Go SSL (staging) | No | No | `buypass.com` |
| `GoogleTrustServices` | Google Trust Services | Yes | No | `pki.goog` |
| `SslCom` | SSL.com | Yes | No | `ssl.com` |
| `CustomProvider` | Any RFC 8555-compliant CA | Optional | Optional | configurable (default: skip) |

### Let's Encrypt

```php
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;

// Production: issues browser-trusted certificates
CoyoteCert::with(new LetsEncrypt())

// Staging: rate-limit-free, not browser-trusted; use during development
CoyoteCert::with(new LetsEncryptStaging())
```

### ZeroSSL

ZeroSSL requires EAB credentials. CoyoteCert can provision them automatically from your API key, or you can supply pre-provisioned credentials directly.

```php
use CoyoteCert\Provider\ZeroSSL;

// Automatic provisioning: CoyoteCert fetches EAB credentials from the ZeroSSL API
CoyoteCert::with(new ZeroSSL(apiKey: 'your-zerossl-api-key'))
    ->email('admin@example.com') // required for auto-provisioning

// Manual credentials: skip the API call
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
use CoyoteCert\Enums\EabAlgorithm;

CoyoteCert::with(new CustomProvider(
    directoryUrl:      'https://acme.example.com/directory',
    displayName:       'My Internal CA',  // used in log messages
    eabKid:            'kid',             // omit if EAB not required
    eabHmac:           'hmac',
    verifyTls:         true,
    profilesSupported: false,
    eabAlgorithm:      EabAlgorithm::HS256, // HS256 (default), HS384, or HS512
    caaIdentifiers:    ['myca.com'],      // CAA values that permit this CA; omit to skip CAA check
))
```

---

## Challenge handlers

ACME requires you to prove domain ownership by completing a challenge. CoyoteCert ships with an HTTP-01 handler and abstract bases for DNS-persist-01 and TLS-ALPN-01. DNS-01 is implemented via the `ChallengeHandlerInterface`.

### http-01

The simplest challenge type. CoyoteCert writes a token file to your web root; the CA fetches it over HTTP.

```php
use CoyoteCert\Challenge\Http01Handler;

->challenge(new Http01Handler('/var/www/html'))
```

The file is written to `{webroot}/.well-known/acme-challenge/{token}` and removed automatically after validation. Your web server must serve it as plain text without authentication.

### dns-01

Deploy a TXT record at `_acme-challenge.{domain}` and remove it after validation.

CoyoteCert ships built-in handlers for Cloudflare, Hetzner DNS, DigitalOcean, ClouDNS, AWS Route53, and shell scripts. See [DNS-01 providers](#dns-01-providers) for full details and library usage.

To implement a custom handler, use `ChallengeHandlerInterface`:

```php
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Interfaces\ChallengeHandlerInterface;

class MyDns01Handler implements ChallengeHandlerInterface
{
    public function supports(AuthorizationChallengeEnum $type): bool
    {
        return $type === AuthorizationChallengeEnum::DNS;
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        // $keyAuthorization is the value to put in the TXT record
        MyDns::setTxtRecord('_acme-challenge.' . $domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        MyDns::deleteTxtRecord('_acme-challenge.' . $domain);
    }
}
```

```php
->challenge(new MyDns01Handler())
```

DNS-01 is the only challenge type that supports wildcard certificates (`*.example.com`).

### dns-persist-01

A CoyoteCert-specific strategy where the TXT record is deployed once and kept in place permanently. On every subsequent renewal, the CA validates against the same record. No DNS propagation wait, no deploy/cleanup cycle.

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

### tls-alpn-01

Defined in [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737). The CA opens a TLS connection to port 443 of the domain and negotiates the `acme-tls/1` ALPN protocol. The server must present a self-signed certificate that contains a critical `id-pe-acmeIdentifier` extension (OID `1.3.6.1.5.5.7.1.31`) whose value is the SHA-256 digest of the key authorization. No port 80 access required.

Extend `TlsAlpn01Handler` and implement `deploy()` and `cleanup()`. Call `generateAcmeCertificate()` inside `deploy()` to obtain the certificate and key; it handles all the RFC 8737 encoding automatically.

```php
use CoyoteCert\Challenge\TlsAlpn01Handler;

class MyTlsAlpn01Handler extends TlsAlpn01Handler
{
    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        ['cert' => $certPem, 'key' => $keyPem] =
            $this->generateAcmeCertificate($domain, $keyAuthorization);

        // Configure your TLS server to present $certPem/$keyPem for acme-tls/1
        // connections on port 443, then reload it.
        MyServer::loadAcmeCert($domain, $certPem, $keyPem);
    }

    public function cleanup(string $domain, string $token): void
    {
        MyServer::removeAcmeCert($domain);
    }
}
```

```php
->challenge(new MyTlsAlpn01Handler())
```

> **Note:** TLS-ALPN-01 validates on port 443 only and does not require port 80. It is supported by Caddy, nginx (with the ACME plugin), and HAProxy. Wildcard certificates are not supported; use DNS-01 for those.

---

## DNS-01 providers

CoyoteCert ships built-in DNS-01 handlers for six providers. Every handler extends `AbstractDns01Handler`, which runs a post-deploy propagation check by default and exposes three fluent controls:

```php
// All return a new immutable instance.
$handler->propagationTimeout(120)    // seconds to poll for the TXT record (default: 60)
$handler->propagationDelay(10)       // fixed pause after the check, for slow secondaries (default: 0)
$handler->skipPropagationCheck()     // skip polling entirely (split-horizon / internal DNS)
```

Zone detection is automatic: the handler walks the domain's public-suffix candidates (`sub.example.com` → `example.com`) until it finds a matching zone in the API. Supply an explicit zone to skip the detection call.

### Cloudflare

Requires an API token with `Zone.DNS:Edit` permission. Detects the zone automatically.

```php
use CoyoteCert\Challenge\Dns\CloudflareDns01Handler;

$handler = new CloudflareDns01Handler(apiToken: 'your-api-token');

// With explicit zone ID (skips zone detection)
$handler = new CloudflareDns01Handler(apiToken: 'your-api-token', zoneId: 'zone-id');
```

```php
->challenge($handler->propagationTimeout(90))
```

### Hetzner DNS

Requires an API token from the [Hetzner DNS Console](https://dns.hetzner.com).

```php
use CoyoteCert\Challenge\Dns\HetznerDns01Handler;

$handler = new HetznerDns01Handler(apiToken: 'your-api-token');

// With explicit zone ID
$handler = new HetznerDns01Handler(apiToken: 'your-api-token', zoneId: 'zone-id');
```

### DigitalOcean

Requires a personal access token with write access to domains.

```php
use CoyoteCert\Challenge\Dns\DigitalOceanDns01Handler;

$handler = new DigitalOceanDns01Handler(apiToken: 'your-api-token');

// With explicit zone name
$handler = new DigitalOceanDns01Handler(apiToken: 'your-api-token', zone: 'example.com');
```

### ClouDNS

Requires a ClouDNS auth-id and auth-password from your account panel.

```php
use CoyoteCert\Challenge\Dns\ClouDnsDns01Handler;

$handler = new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret');

// With explicit zone name
$handler = new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret', zone: 'example.com');
```

### AWS Route53

No AWS SDK required — SigV4 request signing is implemented directly with `hash_hmac()` and `hash()`. Requires an IAM user or role with `route53:ChangeResourceRecordSets` and `route53:ListHostedZonesByName` permissions.

```php
use CoyoteCert\Challenge\Dns\Route53Dns01Handler;

$handler = new Route53Dns01Handler(
    accessKeyId:     'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
);

// With explicit zone ID (with or without the /hostedzone/ prefix)
$handler = new Route53Dns01Handler(
    accessKeyId:     'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    zoneId:          'Z1D633PJN98FT9',
);
```

### Shell / exec

Delegates to any command-line tool — useful for `nsupdate`, acme.sh hook scripts, or a custom DNS CLI. Use `{domain}` and `{keyauth}` as placeholders in the command template. The values are also injected as `ACME_DOMAIN` and `ACME_KEYAUTH` environment variables for scripts that prefer the environment.

```php
use CoyoteCert\Challenge\Dns\ShellDns01Handler;

// Single command for deploy; no cleanup
$handler = new ShellDns01Handler('/usr/local/bin/dns-hook {domain} {keyauth}');

// Separate deploy and cleanup commands
$handler = new ShellDns01Handler(
    deployCommand:  '/usr/local/bin/dns-hook add {domain} {keyauth}',
    cleanupCommand: '/usr/local/bin/dns-hook del {domain}',
);
```

A non-zero exit code throws `ChallengeException`.

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
| `/var/certs/{domain}.{KeyType}.cert.json` | Serialised `StoredCertificate` (e.g. `example.com.EC_P256.cert.json`) |

The directory is created automatically (mode 0700). Reads use shared locks, writes use exclusive locks, safe for concurrent processes.

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

Implement `StorageInterface` with eight methods:

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

    public function hasCertificate(string $domain, KeyType $keyType): bool
    {
        return (bool) $this->redis->exists("acme:cert:{$domain}:{$keyType->value}");
    }

    public function getCertificate(string $domain, KeyType $keyType): ?StoredCertificate
    {
        $json = $this->redis->get("acme:cert:{$domain}:{$keyType->value}");
        return $json ? StoredCertificate::fromArray(json_decode($json, true)) : null;
    }

    public function saveCertificate(string $domain, StoredCertificate $cert): void
    {
        $this->redis->set("acme:cert:{$domain}:{$cert->keyType->value}", json_encode($cert->toArray()));
    }

    public function deleteCertificate(string $domain, KeyType $keyType): void
    {
        $this->redis->del("acme:cert:{$domain}:{$keyType->value}");
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
    ->identifiers('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issue();
```

### issueOrRenew()

The recommended method for production. Returns the existing certificate if it is still valid; issues a new one otherwise. Accepts an optional `$daysBeforeExpiry` threshold (default 30).

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew(daysBeforeExpiry: 30);
```

Run this in a cron job or scheduler. Safe to call as often as you like; it does nothing when the certificate is still valid.

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
    ->identifiers('example.com');

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

## Event callbacks

Register callbacks on the builder to react to certificate lifecycle events without subclassing or parsing log output. Useful for reloading a web server, pushing secrets to a vault, or sending a Slack notification.

### onIssued

Fires after every successful certificate issuance, first-time or renewal.

```php
CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->onIssued(function (StoredCertificate $cert): void {
        SecretsManager::push('tls/example.com', [
            'cert'     => $cert->certificate,
            'key'      => $cert->privateKey,
            'fullchain'=> $cert->fullchain,
        ]);
    })
    ->issueOrRenew();
```

### onRenewed

Fires only when an existing certificate is replaced (i.e. storage already held a cert before the new one was issued). Fires after `onIssued` callbacks.

```php
CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->onIssued(fn($cert) => SecretsManager::push('tls/example.com', $cert->toArray()))
    ->onRenewed(fn($cert) => Nginx::reload())
    ->issueOrRenew();
```

Both methods accept any `callable` and can be called multiple times. Callbacks run in registration order, after the certificate has been saved to storage.

---

## CAA pre-check

[CAA (Certification Authority Authorization)](https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization) is a DNS record type that restricts which CAs are allowed to issue certificates for a domain. If `example.com` has `CAA 0 issue "digicert.com"`, Let's Encrypt will refuse the order, but only after you have consumed a rate-limit attempt and waited for the ACME workflow to fail.

CoyoteCert runs the CAA check itself before submitting anything to the CA. If the records block the chosen CA, you get a `CaaException` immediately:

```php
use CoyoteCert\Exceptions\CaaException;

try {
    $cert = CoyoteCert::with(new LetsEncrypt())
        ->identifiers('example.com')
        ->challenge(new Http01Handler('/var/www/html'))
        ->issue();
} catch (CaaException $e) {
    // e.g. 'CAA records for "example.com" do not permit issuance by this CA
    //       (expected one of: letsencrypt.org).'
    echo $e->getMessage();
}
```

### How the check works

1. For each domain in `->identifiers()`, CoyoteCert queries CAA records at the exact name.
2. If no records are found, it walks up one label at a time (`sub.example.com` → `example.com`) until records are found or the second-level domain is exhausted.
3. If no records exist anywhere in the tree, the domain has an open policy and any CA may issue.
4. For wildcard domains (`*.example.com`), `issuewild` records are checked first; the check falls back to `issue` records if no `issuewild` records exist.
5. Parameter extensions after a semicolon (`letsencrypt.org; validationmethods=http-01`) are stripped before comparison.

`CaaException` extends `AcmeException`, so existing catch blocks for the base type continue to work.

IP address identifiers are excluded from the CAA check; CAA records apply to domain names only.

### Opting out

Skip the CAA check when DNS is internal, split-horizon, or otherwise unreachable from the issuing host:

```php
CoyoteCert::with(new LetsEncrypt())
    ->identifiers('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->skipCaaCheck()
    ->issue();
```

`Pebble` and `CustomProvider` (without explicit `caaIdentifiers`) skip the check automatically, since their CAA identifiers are unknown.

---

## Error handling

All exceptions extend `AcmeException`, so a single `catch (AcmeException $e)` covers everything. Catch the narrower types when you need to react differently to specific failure modes.

### Rate limits: Retry-After included

```php
use CoyoteCert\Exceptions\RateLimitException;

try {
    $cert = CoyoteCert::with(new LetsEncrypt())
        ->identifiers('example.com')
        ->challenge(new Http01Handler('/var/www/html'))
        ->issue();
} catch (RateLimitException $e) {
    $wait = $e->getRetryAfter(); // int seconds from Retry-After header, or null
    echo "Rate limited. Retry" . ($wait ? " in {$wait}s." : " later.");
}
```

`getRetryAfter()` returns the value from the CA's `Retry-After` header when present, or `null` when the header is absent. Use it to schedule a precise back-off rather than guessing.

### Authentication failures

```php
use CoyoteCert\Exceptions\AuthException;

try {
    $api->account()->get();
} catch (AuthException $e) {
    // 401 / 403: account key rejected or credentials revoked
    echo $e->getMessage();
}
```

`AuthException` is thrown on 401 and 403 responses. Distinct from a rate limit or a transient server error, so you can alert or re-provision credentials rather than retrying.

### Per-identifier subproblems (RFC 8555 §6.7)

When an order covering multiple domains is rejected, the CA may return a `subproblems` array with a separate error for each failing identifier:

```php
use CoyoteCert\Exceptions\AcmeException;

try {
    $cert = CoyoteCert::with(new LetsEncrypt())
        ->identifiers(['example.com', 'bad.example.com'])
        ->challenge(new Http01Handler('/var/www/html'))
        ->issue();
} catch (AcmeException $e) {
    foreach ($e->getSubproblems() as $sub) {
        // ['type' => '...', 'detail' => '...', 'identifier' => ['type' => 'dns', 'value' => '...']]
        echo $sub['identifier']['value'] . ': ' . $sub['detail'] . PHP_EOL;
    }
}
```

`getSubproblems()` returns an empty array when the server returned a single top-level error with no per-identifier breakdown.

### Exception hierarchy

```
AcmeException          - base; always safe to catch
├── AuthException      - 401/403 (bad credentials, revoked account)
├── RateLimitException - 429 (too many requests); carries getRetryAfter()
├── CaaException       - CAA DNS record blocks issuance
├── ChallengeException - challenge validation failed
├── CryptoException    - local key or certificate operation failed
├── DomainValidationException - pre-flight HTTP/DNS self-check failed
├── OrderNotFoundException   - order ID not found on the CA
└── StorageException   - storage backend error
```

---

## Wildcard and multi-domain certificates

Pass an array of domains to `->identifiers()`. Wildcards require DNS-01 or dns-persist-01.

```php
// Multi-domain (SAN) certificate via HTTP-01
CoyoteCert::with(new LetsEncrypt())
    ->identifiers(['example.com', 'www.example.com', 'api.example.com'])
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew();

// Wildcard certificate via DNS-01
CoyoteCert::with(new LetsEncrypt())
    ->identifiers(['example.com', '*.example.com'])
    ->challenge(new CloudflareDns01Handler())
    ->issueOrRenew();
```

`*.example.com` covers one label deep (`sub.example.com`) but not the apex (`example.com`). Include both if you need both.

`->identifiers()` validates every entry against RFC-compliant hostname syntax (or as an IP address) and throws an `AcmeException` immediately for malformed input, so misconfigured lists are caught before any CA communication starts.

---

## IP address certificates (RFC 8738)

`->identifiers()` accepts IPv4 and IPv6 addresses alongside hostnames. CoyoteCert automatically sets `type: ip` on ACME identifiers and `IP:` SAN entries in the CSR. No extra API calls required.

```php
// IPv4-only certificate (e.g. with Let's Encrypt shortlived profile)
CoyoteCert::with(new LetsEncrypt())
    ->identifiers('192.0.2.1')
    ->profile('shortlived')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew();

// Mixed hostname + IP certificate
CoyoteCert::with(new LetsEncrypt())
    ->identifiers(['example.com', '192.0.2.1', '2001:db8::1'])
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew();
```

IP SANs are validated via HTTP-01 (the CA connects to the IP directly). Wildcards cannot be combined with IP identifiers.

Not all CAs support IP SANs; check your CA's documentation. Let's Encrypt supports them on both the `classic` and `shortlived` profiles.

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
    ->identifiers(['example.com', 'www.example.com'])
    ->challenge(new Http01Handler('/var/www/html'))
    ->logger($logger)
    ->onRenewed(fn($cert) => exec('systemctl reload nginx'))
    ->issueOrRenew(daysBeforeExpiry: 30);
```

Add to crontab. Daily is sufficient; `issueOrRenew()` skips the CA call when nothing is due:

```
0 3 * * * php /usr/local/bin/renew-certs.php
```

---

## ARI: CA-guided renewal windows

[RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) lets a CA advertise a specific time window during which it wants you to renew. CoyoteCert checks the ARI endpoint automatically when `needsRenewal()` or `issueOrRenew()` is called.

- If the CA exposes a `renewalInfo` URL in its directory and the renewal window is currently open, `needsRenewal()` returns `true` even if the certificate has more than `$daysBeforeExpiry` days remaining.
- If the ARI request fails (network error, non-200 response), CoyoteCert falls back to the `$daysBeforeExpiry` threshold silently.
- If the CA does not support ARI (no `renewalInfo` in the directory), the threshold is used exclusively.

No configuration is required. CoyoteCert handles this transparently.

---

## ACME profiles

Profiles let you request a specific certificate type from the CA. Let's Encrypt currently supports two:

```php
->profile('shortlived') // 6-day certificate, no OCSP/CRL infrastructure needed
->profile('classic')    // 90-day certificate (default if no profile specified)
```

Short-lived certificates are renewed more frequently but eliminate the need for OCSP stapling, CRL checks, and revocation infrastructure. Much simpler to operate.

Profiles are forwarded to the CA only if the provider reports `supportsProfiles() === true`. For CAs that don't support profiles (ZeroSSL, Buypass, etc.) the setting is silently ignored, so you can call `->profile()` unconditionally.

---

## Preferred chain selection

Some CAs offer multiple certificate chains via `Link: rel="alternate"` headers (RFC 8555 §7.4.2). Let's Encrypt uses this to serve both the ISRG Root X1 chain and older cross-signed chains.

Use `->preferredChain()` to request a specific chain by matching against the Common Name or Organisation of the intermediate certificates. The match is a case-insensitive substring, so partial names work fine.

```php
// Prefer the ISRG Root X1 chain (shorter, no DST cross-signature)
CoyoteCert::with(new LetsEncrypt())
    ->identifiers('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->preferredChain('ISRG Root X1')
    ->issueOrRenew();
```

If no alternate chain matches, CoyoteCert falls back to the default chain returned by the CA, so this call is always safe to include even when the CA offers only one chain.

When using the low-level API directly, pass the preference as a second argument to `getBundle()`:

```php
$bundle = $api->certificate()->getBundle($order, 'ISRG Root X1');
```

---

## Key types

```php
use CoyoteCert\Enums\KeyType;

// Certificate key type (default: EC_P256)
->keyType(KeyType::EC_P256)   // ECDSA P-256: fast, compact, widely supported
->keyType(KeyType::EC_P384)   // ECDSA P-384: higher security margin
->keyType(KeyType::RSA_2048)  // RSA 2048-bit
->keyType(KeyType::RSA_4096)  // RSA 4096-bit: maximum compatibility

// ACME account key type (default: EC_P256)
->accountKeyType(KeyType::RSA_2048)
```

EC P-256 is the default for both the certificate and the account key. It produces smaller keys and faster TLS handshakes than RSA while being accepted by all major CAs and browsers.

---

## Certificate revocation

Revoke a stored certificate with an optional RFC 5280 reason code.

```php
use CoyoteCert\CoyoteCert;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Enums\RevocationReason;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

$storage = new FilesystemStorage('/var/certs');
$coyote  = CoyoteCert::with(new LetsEncrypt())->storage($storage);

$cert = $storage->getCertificate('example.com', KeyType::EC_P256);

$coyote->revoke($cert);                                              // Unspecified (default)
$coyote->revoke($cert, RevocationReason::KeyCompromise);
$coyote->revoke($cert, RevocationReason::CaCompromise);
$coyote->revoke($cert, RevocationReason::AffiliationChanged);
$coyote->revoke($cert, RevocationReason::Superseded);
$coyote->revoke($cert, RevocationReason::CessationOfOperation);
$coyote->revoke($cert, RevocationReason::CertificateHold);
$coyote->revoke($cert, RevocationReason::PrivilegeWithdrawn);
$coyote->revoke($cert, RevocationReason::AaCompromise);
```

Returns `true` on success, `false` if the CA rejected the request.

After revoking, remove the stored certificate so `issueOrRenew()` will request a fresh one:

```php
$storage->deleteCertificate('example.com', KeyType::EC_P256);
```

---

## PSR-18 HTTP client

CoyoteCert ships with a built-in curl client that requires no extra dependencies. To use a custom HTTP client, pass any PSR-18 `ClientInterface`:

```php
// Symfony HttpClient: implements all three interfaces itself
->httpClient(new \Symfony\Component\HttpClient\Psr18Client())

// Guzzle: pass request and stream factories separately
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;

->httpClient(
    new Client(),
    new HttpFactory(), // RequestFactoryInterface
    new HttpFactory(), // StreamFactoryInterface: same object works for both
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

If a custom PSR-18 client is configured, this call has no effect. Configure the timeout in your client directly.

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
$cert->certificate  // string: PEM leaf certificate
$cert->privateKey   // string: PEM private key
$cert->fullchain    // string: PEM leaf + intermediate chain
$cert->caBundle     // string: PEM intermediate chain only
$cert->issuedAt     // DateTimeImmutable
$cert->expiresAt    // DateTimeImmutable
$cert->domains      // string[]: domains as recorded at issuance time
```

### Methods

```php
// Quick expiry checks
$cert->isExpired();              // bool: true if the cert is past its expiry
$cert->expiresWithin(30);        // bool: true if expiry is ≤ 30 days away

// Days until expiry (0 if already expired)
$cert->remainingDays();

// Ceiling of days until expiry (negative if expired)
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
CoyoteCert::with(AcmeProviderInterface $provider)  // factory: select the CA
```

| Method | Type | Default | Description |
|---|---|---|---|
| `->email(string)` | fluent | `''` | Contact email; required for ZeroSSL auto-provisioning |
| `->identifiers(string\|array)` | fluent | - | Domain(s) and/or IP(s) to certify; first entry is the primary |
| `->challenge(ChallengeHandlerInterface)` | fluent | - | Challenge handler |
| `->storage(StorageInterface)` | fluent | none | Storage backend |
| `->keyType(KeyType)` | fluent | `EC_P256` | Certificate key algorithm |
| `->accountKeyType(KeyType)` | fluent | `EC_P256` | ACME account key algorithm |
| `->profile(string)` | fluent | `''` | ACME profile (`shortlived`, `classic`) |
| `->httpClient(ClientInterface, ...)` | fluent | built-in curl | PSR-18 HTTP client |
| `->withHttpTimeout(int)` | fluent | `10` | Curl timeout in seconds |
| `->logger(LoggerInterface)` | fluent | none | PSR-3 logger |
| `->preferredChain(string)` | fluent | `''` | Preferred chain issuer CN/O (RFC 8555 §7.4.2); falls back to default chain if no match |
| `->skipLocalTest()` | fluent | off | Disable pre-flight HTTP/DNS self-check |
| `->skipCaaCheck()` | fluent | off | Disable CAA DNS pre-check (internal CAs, split-horizon DNS) |
| `->onIssued(callable)` | fluent | none | Callback fired after every successful issuance; receives `StoredCertificate` |
| `->onRenewed(callable)` | fluent | none | Callback fired when an existing cert is replaced; receives `StoredCertificate` |
| `->issue()` | terminal | - | Issue unconditionally; returns `StoredCertificate` |
| `->renew()` | terminal | - | Alias for `issue()` |
| `->issueOrRenew(int $days = 30)` | terminal | - | Issue only when needed; returns `StoredCertificate` |
| `->needsRenewal(int $days = 30)` | query | - | `true` if renewal is needed |
| `->revoke(StoredCertificate, RevocationReason)` | terminal | - | Revoke a certificate |

---

## Low-level API

For advanced use cases (custom account management, manual order orchestration, scripted key rollovers), the `Api` class exposes every ACME endpoint directly.

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

// Default: connects to localhost:14000, TLS verification enabled
CoyoteCert::with(new Pebble())

// Pebble uses a self-signed CA, so disable TLS verification explicitly
CoyoteCert::with(new Pebble(verifyTls: false))

// Custom URL
CoyoteCert::with(new Pebble(url: 'https://pebble.internal:14000/dir', verifyTls: false))

// With EAB (if Pebble is configured for it)
CoyoteCert::with(new Pebble(verifyTls: false, eab: true, eabKid: 'kid', eabHmac: 'hmac'))
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

This project is maintained by **[Blendbyte](https://www.blendbyte.com)**, a team of engineers with 20+ years of experience building cloud infrastructure, web applications, and developer tools. We use these packages in production and contribute to the open source ecosystem we rely on every day. Issues and PRs are always welcome.

🌐 [blendbyte.com](https://www.blendbyte.com) · 📧 [hello@blendbyte.com](mailto:hello@blendbyte.com)
