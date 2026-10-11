<img alt="coyotecert-banner-2560x1706" src="https://github.com/user-attachments/assets/d5510075-b62c-462f-a941-1d31b48bbec3" />

# CoyoteCert

[![Latest Version on Packagist](https://img.shields.io/packagist/v/blendbyte/coyotecert.svg?style=flat-square)](https://packagist.org/packages/blendbyte/coyotecert)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://github.com/blendbyte/coyotecert/blob/main/LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-787cb5?style=flat-square)](https://www.php.net)
[![Tests](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/tests.yml?branch=main&style=flat-square&label=tests)](https://github.com/blendbyte/coyotecert/actions/workflows/tests.yml)
[![Static Analysis](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/static-analysis.yml?branch=main&style=flat-square&label=phpstan)](https://github.com/blendbyte/coyotecert/actions/workflows/static-analysis.yml)
[![Coverage](https://img.shields.io/codecov/c/github/blendbyte/coyotecert?style=flat-square)](https://codecov.io/gh/blendbyte/coyotecert)

**A PHP 8.3+ ACME v2 client for issuing, renewing, and revoking TLS certificates.** Works with Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, and any RFC 8555-compliant CA. Fluent API, no framework dependencies, solid test coverage.

ACME (Automatic Certificate Management Environment) is the protocol behind free, automated TLS certificates. Yes, same name as the cartoon supply company. We leaned into it. CoyoteCert covers the whole thing: account management, order lifecycle, HTTP-01, DNS-01, and TLS-ALPN-01 challenges, certificate issuance, ARI smart renewal, and revocation. One `composer require blendbyte/coyotecert` and you're off. No cliff. No 🪨.

---

## Contents

- [Why CoyoteCert](#why-coyotecert)
- [Requirements](#requirements)
- [Installation](#installation)
- [Laravel](#laravel)
- [Quick start](#quick-start)
- [Full example: nginx + automatic renewal](#full-example-nginx--automatic-renewal)
- [CLI](#cli)
- [Providers](#providers)
- [Challenge handlers](#challenge-handlers)
- [DNS-01 providers](#dns-01-providers)
- [Storage backends](#storage-backends)
- [Issuing certificates](#issuing-certificates)
- [Event callbacks](#event-callbacks)
- [CAA pre-check](#caa-pre-check)
- [Error handling](#error-handling)
- [Wildcard and multi-domain certificates](#wildcard-and-multi-domain-certificates)
- [IP address certificates](#ip-address-certificates-rfc-8738)
- [Automatic renewal](#automatic-renewal)
- [ARI: CA-guided renewal windows](#ari-ca-guided-renewal-windows)
- [ACME profiles](#acme-profiles)
- [Preferred chain selection](#preferred-chain-selection)
- [Key types](#key-types)
- [Certificate revocation](#certificate-revocation)
- [Security](#security)
- [PSR-18 HTTP client](#psr-18-http-client)
- [HTTP timeout](#http-timeout)
- [Logging](#logging)
- [Inspecting StoredCertificate](#inspecting-storedcertificate)
- [Builder reference](#builder-reference)
- [Low-level API](#low-level-api)
- [Testing with Pebble](#testing-with-pebble)

---

## Why CoyoteCert

### How it stacks up

Every other crate in the ACME catalogue makes you do at least one of these manually: fetch EAB credentials, wire up a DNS provider, write the CLI wrapper, figure out ARI yourself. This one comes pre-loaded.

| Feature | **CoyoteCert** | [ACMECert](https://github.com/skoerfgen/ACMECert) | [acmephp](https://github.com/acmephp/acmephp) | [kelunik/acme](https://github.com/kelunik/acme) | [yaac](https://github.com/afosto/yaac) |
|---|:---:|:---:|:---:|:---:|:---:|
| ARI (RFC 9773) | ✅ | ✅ | ❌ | ❌ | ❌ |
| EAB auto-provisioning ¹ | ✅ | manual | manual | ❌ | ❌ |
| IP SANs (RFC 8738) | ✅ | ✅ | ❌ | ❌ | ❌ |
| TLS-ALPN-01 | ✅ | ✅ | ❌ | ❌ | ❌ |
| Built-in DNS providers | **6** | — | 3 | — | — |
| CLI shipped with package | ✅ | — | ✅ | — | — |
| Laravel integration | ✅ | — | — | — | — |

<sup>¹ "auto-provisioning" means CoyoteCert fetches EAB credentials directly from the ZeroSSL API key (no copy-pasting tokens). "manual" means EAB is supported but credentials are your problem.</sup>

Cells verified from each library's public repository, May 2026. If something's changed, open a PR. We check before merging.

### Every major CA, out of the box

Built-in providers for Let's Encrypt, ZeroSSL, Google Trust Services, and SSL.com. Full EAB support included; ZeroSSL auto-provisions credentials from your API key, no token copy-pasting. Need something more exotic? `CustomProvider` handles any RFC 8555-compliant CA.

### A CLI that ships with the package

`coyote issue` and `coyote status` come in the box. Issue a certificate with one command, inspect it with another. Drop it anywhere certbot or acme.sh would go in a PHP stack: same providers, same key types, same storage paths, cron-friendly exit codes.

### Storage that fits wherever you are

Filesystem with file locking, PDO for MySQL/PostgreSQL/SQLite, and in-memory for tests, all sharing the same interface. Switching backends never touches your issuance code.

### Six DNS-01 providers, no extra SDK needed

Cloudflare, Hetzner DNS, DigitalOcean, ClouDNS, AWS Route53, and shell/exec, all with automatic zone detection, post-deploy propagation checking, and fluent timeout controls. Route53 handles SigV4 signing itself; no AWS SDK required. Wildcards need DNS-01, and CoyoteCert has the providers covered.

### 🪨 Fails fast, before it costs you

CoyoteCert checks CAA DNS records for every domain before touching the CA. If a record blocks your chosen CA, you get a `CaaException` immediately, not after burning a rate-limit attempt. Same pre-flight logic verifies your HTTP token or DNS TXT record locally before the CA comes knocking. Unlike a certain cartoon coyote, we check for obstacles before ordering supplies.

### Typed exceptions that tell you what actually went wrong

`RateLimitException` carries the CA's `Retry-After` seconds so your retry logic is precise. `AuthException` means bad credentials, not a transient blip. `AcmeException::getSubproblems()` tells you exactly which domain in a multi-domain order was rejected and why.

### Short-lived certificates and ACME profiles

Let's Encrypt's `shortlived` profile gives you 6-day certs with no OCSP or CRL overhead. CoyoteCert passes the profile through and quietly ignores it on CAs that haven't caught up yet. Call `->profile()` unconditionally.

### RFC 8555 + RFC 9773, done right

Proper nonce handling with automatic retry on `badNonce`, JWS signing for every request, EAB for CAs that require it, and ARI (RFC 9773) so renewal windows are set by the CA rather than a fixed calendar guess.

### No default CA, no hidden opinions

CoyoteCert has no default CA. Every call requires an explicit provider. Trust store coverage, rate limits, certificate lifetime, EAB requirements, data residency. Those trade-offs are yours, not ours.

### Also worth knowing

**ECDSA-first:** keys default to EC P-256; EC P-384, RSA-2048, and RSA-4096 are all there.

**IP address certificates** (RFC 8738): pass an IP to `->identifiers()` and it works. `type: ip` on the order, `IP:` SANs in the CSR, no extra setup.

**PSR-18 HTTP client:** the built-in curl client needs no extra dependencies; swap it for any PSR-18 client with one builder call.

**94%+ test coverage:** unit tests with mocked responses plus a live [Pebble](https://github.com/letsencrypt/pebble) integration suite across PHP 8.3, 8.4, and 8.5. No mock-only false confidence.

**Modern PHP:** strict types, backed enums, readonly constructor promotion. No magic methods, no global state.

**Truly independent:** no CA affiliation, not maintained or financed by one.

---

## Requirements

PHP ^8.3 with `ext-curl`, `ext-json`, and `ext-openssl`.

---

## Installation

```bash
composer require blendbyte/coyotecert
```

---

## Laravel

First-party Laravel integration is available as a separate package: [`blendbyte/coyotecert-laravel`](https://github.com/blendbyte/coyotecert-laravel).

Adds a service provider, config file, Artisan commands (`cert:issue`, `cert:renew`, `cert:status`, `cert:revoke`), HTTP-01 challenge served through your app via the cache store (no web server changes, works behind load balancers), Laravel Events, queue job support for DNS-01, and a daily scheduled renewal task. No boilerplate beyond publishing the config.

```php
// In a Laravel app
use Blendbyte\CoyoteCertLaravel\Facades\Cert;

Cert::for('example.com')->issueOrRenew();
```

Full docs and installation in the [companion repo](https://github.com/blendbyte/coyotecert-laravel).

---

## Quick start

**HTTP-01** write a token to your web root:

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
```

**DNS-01** deploy a TXT record via a DNS provider (required for wildcards):

```php
use CoyoteCert\CoyoteCert;
use CoyoteCert\Challenge\Dns\CloudflareDns01Handler;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers(['example.com', '*.example.com'])
    ->email('admin@example.com')
    ->challenge(new CloudflareDns01Handler(apiToken: 'your-api-token'))
    ->issueOrRenew();
```

Both return the same value object:

```php
echo $cert->certificate; // PEM leaf certificate
echo $cert->privateKey;  // PEM private key
echo $cert->fullchain;   // PEM leaf + intermediates
echo $cert->caBundle;    // PEM intermediate chain
```

---

## Full example: nginx + automatic renewal

A complete production setup: certificate issuance, PEM files on disk, nginx pointed at them, automatic reload on renewal, and a daily cron job.

**`/usr/local/bin/renew-certs.php`**

```php
<?php

require __DIR__ . '/../vendor/autoload.php';

use CoyoteCert\CoyoteCert;
use CoyoteCert\Challenge\Http01Handler;
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Storage\FilesystemStorage;

CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/etc/certs'))
    ->identifiers(['example.com', 'www.example.com'])
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->onRenewed(fn() => exec('systemctl reload nginx'))
    ->issueOrRenew();
```

On first run this creates the ACME account and issues the certificate. On subsequent runs it does nothing until renewal is due (when the CA's ARI window opens, or once a third of the certificate's lifetime remains), then issues a new certificate and reloads nginx automatically.

Files written to `/etc/certs/`:

```
account-letsencrypt.pem
account-letsencrypt.json
example.com.EC_P256.cert.json
example.com.EC_P256.certificate.pem
example.com.EC_P256.fullchain.pem    ← point nginx here
example.com.EC_P256.ca.pem
example.com.EC_P256.private_key.pem  ← and here
```

**`/etc/nginx/sites-available/example.com`**

```nginx
server {
    listen 80;
    server_name example.com www.example.com;

    # Required for HTTP-01 challenge validation
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name example.com www.example.com;

    ssl_certificate     /etc/certs/example.com.EC_P256.fullchain.pem;
    ssl_certificate_key /etc/certs/example.com.EC_P256.private_key.pem;

    # ... the rest of your config
}
```

**Cron, daily at 03:00, idempotent:**

```bash
# Recommended: randomize the start time to spread load on the CA
0 3 * * * sleep $((RANDOM % 3600)) && php /usr/local/bin/renew-certs.php
```

Randomizing the start time within the hour avoids stampeding the CA at the same minute as everyone else's cron job. Let's Encrypt explicitly requests this.

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

**HTTP-01:**

```bash
coyote issue \
  --identifier example.com \
  --identifier www.example.com \
  --webroot /var/www/html \
  --email admin@example.com \
  --provider letsencrypt \
  --storage /etc/certs
```

**DNS-01** (required for wildcards). Set the provider's credentials as environment variables, then pass `--dns`:

```bash
export CLOUDFLARE_API_TOKEN=your-token

coyote issue \
  --identifier example.com \
  --identifier '*.example.com' \
  --dns cloudflare \
  --email admin@example.com \
  --provider letsencrypt \
  --storage /etc/certs
```

If a valid certificate already exists and expiry is more than `--days` away, the command exits cleanly with no network requests. Pass `--force` to issue regardless.

**Options**

| Option | Short | Default | Description |
|---|---|---|---|
| `--identifier` | `-i` | | Identifier to include on the certificate (domain name or wildcard). Repeat for SANs: `--identifier example.com --identifier www.example.com` |
| `--email` | `-e` | | Contact email registered with the ACME account |
| `--webroot` | `-w` | | Webroot path for HTTP-01. CoyoteCert writes tokens under `.well-known/acme-challenge/` |
| `--dns` | | | DNS provider for DNS-01 challenge. See DNS providers table below. Mutually exclusive with `--webroot` |
| `--dns-propagation-timeout` | | `60` | Seconds to wait for the TXT record to appear in DNS before submitting the challenge to the CA |
| `--dns-propagation-delay` | | `60` | Settle delay in seconds after the propagation check, letting resolver caches expire before validation. Set it to at least the TTL of the `_acme-challenge` record |
| `--dns-skip-propagation` | | | Skip the post-deploy DNS propagation check entirely (split-horizon or internal DNS) |
| `--provider` | `-p` | | CA to use. See provider table below. **Required** |
| `--storage` | `-s` | `./certs` | Directory to read/write certificates and account keys |
| `--days` | | | Renew when fewer than this many days remain. Default: the CA's ARI window, or a third of the lifetime |
| `--key-type` | | `ec256` | Certificate key type: `ec256`, `ec384`, `rsa2048`, `rsa4096` |
| `--force` | `-f` | | Issue a fresh certificate even if the current one is still valid |
| `--skip-caa` | | | Skip CAA DNS pre-check |
| `--skip-local-test` | | | Skip the HTTP pre-flight self-test |
| `--zerossl-key` | | | ZeroSSL API key for automatic EAB provisioning |
| `--eab-kid` | | | EAB key ID (Google Trust Services, SSL.com, or pre-provisioned ZeroSSL) |
| `--eab-hmac` | | | EAB HMAC key |

**Providers**

| `--provider` value | CA |
|---|---|
| `letsencrypt`, `le` | Let's Encrypt (production) |
| `letsencrypt-staging`, `le-staging`, `staging` | Let's Encrypt (staging) |
| `zerossl` | ZeroSSL (use `--zerossl-key` or `--eab-kid`/`--eab-hmac`) |
| `google`, `gts` | Google Trust Services (requires `--eab-kid` and `--eab-hmac`) |
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
coyote status --identifier example.com --storage /etc/certs
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--identifier` | `-i` | | Primary identifier of the certificate to inspect |
| `--storage` | `-s` | `./certs` | Directory where certificates are stored |
| `--key-type` | | `ec256` | Key type to look up: `ec256`, `ec384`, `rsa2048`, `rsa4096` |

The status line reflects time to expiry:

| Status | Condition |
|---|---|
| `Valid` | More than 30 days remaining |
| `Renewal due` | 7–30 days remaining |
| `Expiring soon` | Fewer than 7 days remaining |
| `Expired` | Certificate has passed its expiry date |

### `coyote certs`

List all certificates in a storage directory, sorted by expiry date.

```bash
coyote certs --storage /etc/certs
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--storage` | `-s` | `./certs` | Directory where certificates are stored |

Each row shows the domain(s), key type, status, and expiry date. The status icons and colours match `coyote status`.

### Cron renewal

```bash
# Recommended: randomize the start time to spread load on the CA
0 3 * * * sleep $((RANDOM % 3600)) && coyote issue --identifier example.com --webroot /var/www/html --storage /etc/certs --email admin@example.com
```

The command is idempotent: it does nothing until renewal is due, so running it daily is safe. Randomizing the start time within the hour avoids stampeding the CA at the same minute as everyone else's cron job. Let's Encrypt explicitly requests this. Set it and forget it. Unlike certain Road Runner traps, this actually works unattended. There is no separate `coyote renew` command; `issue` handles both initial issuance and renewal.

### `coyote revoke`

Revoke a stored certificate. The `--provider` must be the same CA that issued the certificate, as the revocation request is signed with your stored ACME account key for that CA.

```bash
coyote revoke \
  --identifier example.com \
  --provider letsencrypt \
  --storage /etc/certs
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--identifier` | `-i` | | Primary identifier of the certificate to revoke |
| `--provider` | `-p` | | CA the certificate was issued by. **Required** |
| `--storage` | `-s` | `./certs` | Directory where certificates are stored |
| `--key-type` | | `ec256` | Key type: `ec256`, `ec384`, `rsa2048`, `rsa4096` |
| `--reason` | | `unspecified` | Revocation reason (see table below) |
| `--zerossl-key` | | | ZeroSSL API key for EAB provisioning |
| `--eab-kid` | | | EAB key ID |
| `--eab-hmac` | | | EAB HMAC key |

**Revocation reasons**

| `--reason` value | Description |
|---|---|
| `unspecified` | No specific reason (default) |
| `keycompromise` | Private key was compromised |
| `cacompromise` | CA was compromised |
| `affiliationchanged` | Domain ownership or affiliation changed |
| `superseded` | Certificate was replaced by a new one |
| `cessationofoperation` | Domain or service is no longer operated |
| `certificatehold` | Temporary hold |
| `privilegewithdrawn` | Privileges for the domain were withdrawn |
| `aacompromise` | Attribute authority compromise |

### Help and version

```bash
coyote --help               # list available commands
coyote --version            # show version
coyote issue --help         # full option reference for issue
coyote status --help        # full option reference for status
coyote certs --help         # full option reference for certs
coyote revoke --help        # full option reference for revoke
```

---

## Providers

CoyoteCert ships with built-in providers for every major public ACME CA. Pick one and go.

| Provider class | CA | EAB | Profiles | CAA identifier |
|---|---|---|---|---|
| `LetsEncrypt` | Let's Encrypt (production) | No | Yes | `letsencrypt.org` |
| `LetsEncryptStaging` | Let's Encrypt (staging) | No | Yes | `letsencrypt.org` |
| `ZeroSSL` | ZeroSSL | Yes | No | `sectigo.com`, `comodoca.com` |
| `GoogleTrustServices` | Google Trust Services | Yes | No | `pki.goog` |
| `SslCom` | SSL.com | Yes | No | `ssl.com` |
| `CustomProvider` | Any RFC 8555-compliant CA | Optional | Optional | configurable (default: skip) |

### Let's Encrypt

Production for real certs, staging for development. No rate limits on staging, but staging certificates aren't browser-trusted.

```php
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;

CoyoteCert::with(new LetsEncrypt())
CoyoteCert::with(new LetsEncryptStaging())
```

### ZeroSSL

Requires EAB credentials. CoyoteCert can provision them automatically from your API key, or accept pre-provisioned credentials directly.

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

Exposes separate endpoints for RSA and ECC certificates.

```php
use CoyoteCert\Provider\SslCom;

// RSA endpoint (default)
CoyoteCert::with(new SslCom(eabKid: 'kid', eabHmac: 'hmac'))

// ECC endpoint
CoyoteCert::with(new SslCom(eabKid: 'kid', eabHmac: 'hmac', ecc: true))
```

### Custom CA

Point CoyoteCert at any ACME-compliant directory URL: internal CAs, private PKI, whatever you're running.

```php
use CoyoteCert\Provider\CustomProvider;
use CoyoteCert\Enums\EabAlgorithm;

CoyoteCert::with(new CustomProvider(
    directoryUrl:      'https://acme.example.com/directory',
    displayName:       'My Internal CA',
    eabKid:            'kid',             // omit if EAB not required
    eabHmac:           'hmac',
    verifyTls:         true,
    profilesSupported: false,
    eabAlgorithm:      EabAlgorithm::HS256, // HS256 (default), HS384, or HS512
    caaIdentifiers:    ['myca.com'],      // CAA values that permit this CA; omit to skip CAA check
))
```

The storage namespace slug is derived automatically from the directory URL's hostname: `https://acme.example.com/directory` → `acme-example-com`. Call `$provider->getSlug()` to inspect it. This matters when using a custom storage backend alongside `CustomProvider`, since account keys are keyed by slug.

---

## Challenge handlers

ACME requires domain ownership proof via a challenge. CoyoteCert ships with handlers for http-01, dns-01, and tls-alpn-01.

### http-01

CoyoteCert writes a token file to your web root; the CA fetches it over HTTP to confirm domain control.

```php
use CoyoteCert\Challenge\Http01Handler;

->challenge(new Http01Handler('/var/www/html'))
```

The file lands at `{webroot}/.well-known/acme-challenge/{token}` and is removed automatically after validation. Your server must serve it as plain text with no authentication in the way.

### dns-01

Deploy a TXT record at `_acme-challenge.{domain}` and remove it after validation. DNS-01 is the only challenge type that supports wildcard certificates.

CoyoteCert has built-in handlers for Cloudflare, Hetzner DNS, DigitalOcean, ClouDNS, AWS Route53, and shell scripts. See [DNS-01 providers](#dns-01-providers) for full details.

Need something custom? Implement `ChallengeHandlerInterface`:

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

### tls-alpn-01

Defined in [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737). The CA opens a TLS connection to port 443, negotiates `acme-tls/1`, and expects a self-signed certificate with a critical `id-pe-acmeIdentifier` extension containing the SHA-256 digest of the key authorization. No port 80 required.

Extend `TlsAlpn01Handler`, implement `deploy()` and `cleanup()`, and call `generateAcmeCertificate()` to get the RFC 8737-encoded cert and key. No manual DER encoding needed.

```php
use CoyoteCert\Challenge\TlsAlpn01Handler;

class MyTlsAlpn01Handler extends TlsAlpn01Handler
{
    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        ['cert' => $certPem, 'key' => $keyPem] =
            $this->generateAcmeCertificate($domain, $keyAuthorization);

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

> **Note:** TLS-ALPN-01 runs on port 443 only and doesn't touch port 80. It works with Caddy, nginx (ACME plugin), and HAProxy. Wildcards aren't supported; use DNS-01 for those.

---

## DNS-01 providers

Six built-in DNS-01 handlers, all extending `AbstractDns01Handler`, which runs a post-deploy propagation check by default. Every TXT record of an order is written before the check runs, so a wildcard and its base name (which share one `_acme-challenge` name) are never published as a half-complete record set, and the check requires all of that name's values on every authoritative nameserver. A settle delay then lets caching resolvers in front of the CA drop the pre-update answer. Four fluent controls tune the behaviour:

```php
// All return a new immutable instance.
$handler->propagationTimeout(120)    // seconds to poll for the TXT record (default: 60)
$handler->propagationDelay(300)      // settle pause after the check, for resolver caches (default: 60)
$handler->skipPropagationCheck()     // skip polling entirely (split-horizon / internal DNS)
$handler->keepExistingRecords()      // do not delete stale _acme-challenge records before deploying
```

Before deploying a new `_acme-challenge` TXT record, each handler deletes any pre-existing records for that name. This prevents stale records from a previous failed run causing the CA to see multiple values and potentially refuse validation. Call `keepExistingRecords()` to disable this if you manage multiple certificates for the same domain simultaneously and need both records to coexist.

Zone detection is automatic: the handler walks public-suffix candidates (`sub.example.com` → `example.com`) until it finds a match in the API. Supply an explicit zone to skip the detection call entirely.

### Cloudflare

API token with `Zone.DNS:Edit` permission.

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

Uses the [Hetzner Cloud API](https://docs.hetzner.cloud/reference/cloud#tag/zones). Create a read & write API token in the [Hetzner Console](https://console.hetzner.com) under your project's Security > API tokens. Tokens from the retired DNS Console (dns.hetzner.com) no longer work.

```php
use CoyoteCert\Challenge\Dns\HetznerDns01Handler;

$handler = new HetznerDns01Handler(apiToken: 'your-cloud-api-token');

// With explicit zone ID
$handler = new HetznerDns01Handler(apiToken: 'your-cloud-api-token', zoneId: '12345');
```

### DigitalOcean

Personal access token with write access to domains.

```php
use CoyoteCert\Challenge\Dns\DigitalOceanDns01Handler;

$handler = new DigitalOceanDns01Handler(apiToken: 'your-api-token');

// With explicit zone name
$handler = new DigitalOceanDns01Handler(apiToken: 'your-api-token', zone: 'example.com');
```

### ClouDNS

Auth-id and auth-password from your ClouDNS account panel.

```php
use CoyoteCert\Challenge\Dns\ClouDnsDns01Handler;

$handler = new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret');

// With explicit zone name
$handler = new ClouDnsDns01Handler(authId: '12345', authPassword: 'secret', zone: 'example.com');
```

### AWS Route53

No AWS SDK required; SigV4 request signing is implemented directly with `hash_hmac()` and `hash()`. Needs an IAM user or role with `route53:ChangeResourceRecordSets` and `route53:ListHostedZonesByName` permissions.

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

Delegates to any command-line tool: `nsupdate`, acme.sh hook scripts, a custom DNS CLI, whatever. Use `{domain}` and `{keyauth}` as placeholders; values are also injected as `ACME_DOMAIN` and `ACME_KEYAUTH` environment variables for scripts that prefer the environment.

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

Storage persists the ACME account key and issued certificates between runs. Without it, CoyoteCert issues a fresh certificate and creates a new ACME account every time. Probably not what you want.

### Filesystem

```php
use CoyoteCert\Storage\FilesystemStorage;

->storage(new FilesystemStorage('/var/certs'))
```

Files written per certificate:

| File | Mode | Contents |
|---|---|---|
| `/var/certs/account-{provider}.pem` | 0600 | ACME account private key, e.g. `account-letsencrypt.pem` |
| `/var/certs/account-{provider}.json` | 0600 | Account key type metadata |
| `/var/certs/{domain}.{KeyType}.cert.json` | 0600 | Serialised `StoredCertificate` (e.g. `example.com.EC_P256.cert.json`) |
| `/var/certs/{domain}.{KeyType}.certificate.pem` | 0644 | Leaf certificate |
| `/var/certs/{domain}.{KeyType}.private_key.pem` | 0600 | Private key |
| `/var/certs/{domain}.{KeyType}.fullchain.pem` | 0644 | Leaf + intermediate chain |
| `/var/certs/{domain}.{KeyType}.ca.pem` | 0644 | Intermediate chain only |

PEM files are written on every `saveCertificate()` call alongside the JSON, so they're always in sync. Point your web server straight at them:

```nginx
ssl_certificate     /var/certs/example.com.EC_P256.fullchain.pem;
ssl_certificate_key /var/certs/example.com.EC_P256.private_key.pem;
```

The directory is created automatically (mode 0700). Reads use shared locks, writes use exclusive locks, safe for concurrent processes.

### Database (PDO)

Everything in a single key-value table. MySQL/MariaDB, PostgreSQL, and SQLite out of the box.

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

Non-persistent: data is gone when the process exits. Great for tests and one-shot scripts.

```php
use CoyoteCert\Storage\InMemoryStorage;

->storage(new InMemoryStorage())
```

### No storage

If you don't call `->storage()` at all, `issue()` still works and returns a `StoredCertificate`. Nothing is persisted. Useful when your application manages its own persistence (database ORM, secret manager, etc.) and you only want the cert in-hand:

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->identifiers('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issue();

// Store wherever you like
$myVault->put('example.com', $cert->fullchain, $cert->privateKey);
```

Note: without storage, `needsRenewal()` always returns `true` and `issueOrRenew()` will issue on every call. The ACME account key isn't kept either, so every `issue()` registers a new account with the CA. For anything beyond one-off issuance, configure a storage backend (`InMemoryStorage` is enough to reuse one account within a long-running process).

### Custom storage

Implement `StorageInterface` with eight methods:

```php
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Storage\StorageInterface;
use CoyoteCert\Storage\StoredCertificate;

class RedisStorage implements StorageInterface
{
    public function __construct(private \Redis $redis) {}

    public function hasAccountKey(string $providerSlug): bool
    {
        return (bool) $this->redis->exists("acme:{$providerSlug}:account:pem");
    }

    public function getAccountKey(string $providerSlug): string
    {
        return $this->redis->get("acme:{$providerSlug}:account:pem");
    }

    public function getAccountKeyType(string $providerSlug): KeyType
    {
        return KeyType::from($this->redis->get("acme:{$providerSlug}:account:type"));
    }

    public function saveAccountKey(string $providerSlug, string $pem, KeyType $type): void
    {
        $this->redis->set("acme:{$providerSlug}:account:pem", $pem);
        $this->redis->set("acme:{$providerSlug}:account:type", $type->value);
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

The provider slug is passed automatically by CoyoteCert on every account key operation, so multiple CAs never share the same account key. No extra wiring needed.

Built-in providers return fixed slugs (`letsencrypt`, `zerossl`, etc.). `CustomProvider` derives its slug from the directory URL hostname (`acme.example.com` → `acme-example-com`). If you implement `AcmeProviderInterface` directly, `getSlug()` must return a string matching `[a-z0-9][a-z0-9-]*[a-z0-9]`: lowercase, no leading or trailing hyphens. Extending `AbstractProvider` gives you `assertValidSlug()` as a convenience guard.

---

## Issuing certificates

### issue()

Always requests a new certificate from the CA, regardless of what's in storage.

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issue();
```

### issueOrRenew()

The one you want in production. Returns the existing certificate if it's still valid; issues a new one when renewal is due (see [needsRenewal()](#needsrenewal)). Accepts an optional `$daysBeforeExpiry` threshold that replaces the default lifetime rule. Safe to call as often as you like. It does nothing when the certificate is still healthy.

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew();
```

### needsRenewal()

Check whether a renewal is needed without triggering one.

```php
$coyote = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com');

if ($coyote->needsRenewal()) {
    // issue or alert
}
```

Returns `true` when:

- no storage is configured
- no certificate is stored for the primary domain
- the stored certificate has expired, can't be read, or doesn't cover every configured identifier
- the CA's ARI renewal window has opened (see [ARI](#ari-ca-guided-renewal-windows))
- without ARI: a third or less of the certificate's lifetime remains (30 days for a 90-day certificate, 15 for 45 days, 2 for a 6-day `shortlived` one), or fewer than `$daysBeforeExpiry` days when you pass a threshold

---

## Event callbacks

React to certificate lifecycle events without subclassing or parsing log output. Handy for reloading a web server, pushing secrets to a vault, or firing off a Slack notification.

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

Fires only when an existing certificate is replaced (storage already held a cert before the new one was issued). Fires after `onIssued` callbacks.

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

[CAA (Certification Authority Authorization)](https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization) records let domain owners restrict which CAs can issue for them. If `example.com` has `CAA 0 issue "digicert.com"`, Let's Encrypt will reject the order, but only after you've burned a rate-limit attempt and sat through the full ACME workflow.

CoyoteCert checks CAA before talking to the CA. Unlike a certain cartoon coyote, we look before we order from the ACME Corporation:

```php
use CoyoteCert\Exceptions\CaaException;

try {
    $cert = CoyoteCert::with(new LetsEncrypt())
        ->identifiers('example.com')
        ->challenge(new Http01Handler('/var/www/html'))
        ->issue();
} catch (CaaException $e) {
    echo $e->getMessage();
}
```

### How the check works

1. For each domain in `->identifiers()`, CoyoteCert queries CAA records at the exact name.
2. If nothing is found, it walks up one label at a time (`sub.example.com` → `example.com`) until records appear or the second-level domain is exhausted.
3. No records anywhere in the tree means an open policy; any CA may issue.
4. For wildcards (`*.example.com`), `issuewild` records are checked first, falling back to `issue` records if none exist.
5. Parameter extensions after a semicolon (`letsencrypt.org; validationmethods=http-01`) are stripped before comparison.

`CaaException` extends `AcmeException`, so existing catch blocks for the base type keep working. IP address identifiers are excluded. CAA records apply to domain names only.

### Opting out

Skip the CAA check when DNS is internal, split-horizon, or not reachable from the issuing host:

```php
CoyoteCert::with(new LetsEncrypt())
    ->identifiers('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->skipCaaCheck()
    ->issue();
```

`Pebble` and `CustomProvider` (without explicit `caaIdentifiers`) skip the check automatically.

---

## Error handling

All exceptions extend `AcmeException`, so a single `catch (AcmeException $e)` covers everything. Catch the narrower types when you need to respond differently to specific failure modes.

### Rate limits, Retry-After included

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

`getRetryAfter()` returns the value from the CA's `Retry-After` header when present, or `null` when the header is absent.

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

`AuthException` is thrown on 401 and 403 responses, distinct from a rate limit or transient error, so you can alert or re-provision credentials rather than retrying blindly.

### Per-identifier subproblems (RFC 8555 §6.7)

When an order covering multiple domains is rejected, the CA may return a `subproblems` array with a separate error for each failing domain:

```php
use CoyoteCert\Exceptions\AcmeException;

try {
    $cert = CoyoteCert::with(new LetsEncrypt())
        ->identifiers(['example.com', 'bad.example.com'])
        ->challenge(new Http01Handler('/var/www/html'))
        ->issue();
} catch (AcmeException $e) {
    foreach ($e->getSubproblems() as $sub) {
        echo $sub['identifier']['value'] . ': ' . $sub['detail'] . PHP_EOL;
    }
}
```

`getSubproblems()` returns an empty array when the server returned a single top-level error with no per-identifier breakdown. `getProblemType()` returns the CA's ACME error type (for example `urn:ietf:params:acme:error:caa` or `...:rejectedIdentifier`), or `null` for errors raised locally.

### Exception hierarchy

```
AcmeException          - base; always safe to catch
├── AccountNotFoundException - the CA has no account for the stored key (registered automatically by issue())
├── AuthException      - 401/403 (bad credentials, revoked account)
├── RateLimitException - 429 (too many requests); carries getRetryAfter()
├── CaaException       - CAA DNS record blocks issuance
├── ChallengeException - challenge validation failed
├── CryptoException    - local key or certificate operation failed
├── DomainValidationException - pre-flight self-check failed, or the CA marked a challenge invalid
├── OrderNotFoundException   - order ID not found on the CA
└── StorageException   - storage backend error
```

---

## Wildcard and multi-domain certificates

Pass an array of domains to `->identifiers()`. Wildcards need dns-01.

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

`->identifiers()` validates every entry against RFC-compliant hostname syntax (or as an IP address) and throws immediately for malformed input, before any CA communication starts.

---

## IP address certificates (RFC 8738)

`->identifiers()` accepts IPv4 and IPv6 addresses alongside hostnames. CoyoteCert automatically sets `type: ip` on ACME identifiers and `IP:` SAN entries in the CSR. Nothing extra required.

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

IP SANs are validated via HTTP-01 (the CA connects to the IP directly). Wildcards can't be combined with IP identifiers. Not all CAs support IP SANs, so check yours. Let's Encrypt supports them on both `classic` and `shortlived` profiles.

---

## Automatic renewal

The recommended setup: a daily cron job calling `issueOrRenew()`. Here's the full script with PSR-3 logging:

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
    ->issueOrRenew();
```

Add to crontab. Daily is fine; `issueOrRenew()` does nothing until renewal is actually due:

```bash
# Recommended: randomize the start time to spread load on the CA
0 3 * * * sleep $((RANDOM % 3600)) && php /usr/local/bin/renew-certs.php
```

Randomizing the start time within the hour avoids stampeding the CA at the same minute as everyone else's cron job. Let's Encrypt explicitly requests this.

---

## ARI: CA-guided renewal windows

[RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) lets a CA tell you exactly when it wants you to renew: a specific window, not just "X days before expiry." CoyoteCert checks the ARI endpoint automatically whenever `needsRenewal()` or `issueOrRenew()` is called.

- If the CA exposes a `renewalInfo` URL, its window decides: `needsRenewal()` returns `true` once the window has started, including when it has already passed (the CA may be about to revoke the certificate).
- If the ARI request fails or the CA doesn't support ARI, CoyoteCert falls back to the lifetime rule, or to `$daysBeforeExpiry` when you pass one.

No configuration needed. It just works.

---

## ACME profiles

Profiles let you request a specific certificate type from the CA. Let's Encrypt currently supports two:

```php
->profile('shortlived') // 6-day certificate, no OCSP/CRL infrastructure needed
->profile('classic')    // 90-day certificate (default if no profile is set)
```

Short-lived certificates renew more often but eliminate the need for OCSP stapling, CRL checks, and revocation infrastructure. Simpler to operate.

Profiles are forwarded to the CA only if the provider reports `supportsProfiles() === true`. For CAs that don't support profiles, the setting is silently ignored. Call `->profile()` unconditionally if you want.

---

## Preferred chain selection

Some CAs offer multiple certificate chains via `Link: rel="alternate"` headers (RFC 8555 §7.4.2). Let's Encrypt uses this to serve both the ISRG Root X1 chain and older cross-signed chains.

Use `->preferredChain()` to pick the chain that leads to a given root: it matches when the topmost certificate in the chain was issued by that Common Name (case-insensitive, exact name, same as certbot's `--preferred-chain`). The default chain is checked first, then the alternates. If none matches, CoyoteCert falls back to the default chain, always safe to include.

```php
CoyoteCert::with(new LetsEncrypt())
    ->identifiers('example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->preferredChain('ISRG Root X1')
    ->issueOrRenew();
```

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

EC P-256 is the default for both the certificate and the account key. Smaller keys, faster TLS handshakes, accepted by every major CA and browser.

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

Throws `AcmeException` if the CA rejects the request.

After revoking, delete the stored certificate so `issueOrRenew()` requests a fresh one:

```php
$storage->deleteCertificate('example.com', KeyType::EC_P256);
```

---

## Security

Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md). Do not open a public issue.

- **Account keys are sensitive:** back them up, never commit them to git. Treat them like passwords.
- **If the account key is lost,** you can re-register with the CA, but you lose ARI renewal history and any CA-side account associations.
- **Filesystem storage** writes keys at `0600` and the storage directory at `0700`. PEM certificate files are `0644` and are safe to serve publicly.

---

## PSR-18 HTTP client

CoyoteCert ships with a built-in curl client that needs no extra dependencies. To use a custom HTTP client, pass any PSR-18 `ClientInterface`:

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

Tune the built-in curl client's timeout without replacing the whole client:

```php
->withHttpTimeout(30) // seconds
```

Has no effect when a custom PSR-18 client is configured; configure timeout there instead.

---

## Logging

Pass any PSR-3 logger to get debug and info messages throughout the certificate lifecycle:

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

`StoredCertificate` is the value object returned by `issue()` and `issueOrRenew()`. It holds all certificate data and exposes a handful of inspection helpers.

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
CoyoteCert::with(AcmeProviderInterface $provider)  // factory: pick your CA
```

| Method | Type | Default | Description |
|---|---|---|---|
| `->email(string)` | fluent | `''` | Contact email; required for ZeroSSL auto-provisioning |
| `->identifiers(string\|array)` | fluent | | Domain(s) and/or IP(s) to certify; first entry is the primary |
| `->challenge(ChallengeHandlerInterface)` | fluent | | Challenge handler |
| `->storage(StorageInterface)` | fluent | none | Storage backend |
| `->keyType(KeyType)` | fluent | `EC_P256` | Certificate key algorithm |
| `->accountKeyType(KeyType)` | fluent | `EC_P256` | ACME account key algorithm |
| `->profile(string)` | fluent | `''` | ACME profile (`shortlived`, `classic`) |
| `->httpClient(ClientInterface, ...)` | fluent | built-in curl | PSR-18 HTTP client |
| `->withHttpTimeout(int)` | fluent | `10` | Curl timeout in seconds |
| `->logger(LoggerInterface)` | fluent | none | PSR-3 logger |
| `->preferredChain(string)` | fluent | `''` | Common Name of the root the chain should lead to (RFC 8555 §7.4.2); falls back to default if no match |
| `->pollAttempts(int)` | fluent | `10` | Maximum challenge validation poll attempts |
| `->skipLocalTest()` | fluent | off | Disable pre-flight HTTP/DNS self-check |
| `->skipCaaCheck()` | fluent | off | Disable CAA DNS pre-check |
| `->onIssued(callable)` | fluent | none | Callback fired after every successful issuance; receives `StoredCertificate` |
| `->onRenewed(callable)` | fluent | none | Callback fired when an existing cert is replaced; receives `StoredCertificate` |
| `->issue()` | terminal | | Issue unconditionally; returns `StoredCertificate` |
| `->issueOrRenew(int $days = 30)` | terminal | | Issue only when needed; returns `StoredCertificate` |
| `->needsRenewal(int $days = 30)` | query | | `true` if renewal is needed |
| `->revoke(StoredCertificate, RevocationReason)` | terminal | | Revoke a certificate |

---

## Low-level API

For advanced use cases like custom account management, manual order orchestration, and scripted key rollovers, the `Api` class exposes every ACME endpoint directly.

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
$window = $api->renewalInfo()->get($certPem);
$certId = $api->renewalInfo()->certId($certPem);

// Directory
$all    = $api->directory()->all();
$newAcc = $api->directory()->newAccount();
$ariUrl = $api->directory()->renewalInfo(); // null if not supported
```

---

## Testing with Pebble

[Pebble](https://github.com/letsencrypt/pebble) is a small, RFC-compliant ACME test server from the Let's Encrypt team. Run end-to-end tests locally without touching real CA rate limits.

```php
use CoyoteCert\Provider\Pebble;

// Default: connects to localhost:14000
CoyoteCert::with(new Pebble())

// Pebble uses a self-signed CA, disable TLS verification explicitly
CoyoteCert::with(new Pebble(verifyTls: false))

// Custom URL
CoyoteCert::with(new Pebble(url: 'https://pebble.internal:14000/dir', verifyTls: false))

// With EAB (if Pebble is configured for it)
CoyoteCert::with(new Pebble(verifyTls: false, eab: true, eabKid: 'kid', eabHmac: 'hmac'))
```

Docker Compose setup for local development:

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

## Frequently asked questions

### My HTTP-01 validation fails with 404, but the file is sitting right there.

nginx found it first. nginx finds everything first, and usually not in a helpful way.

`location /` swallows the request before it ever reaches `.well-known/acme-challenge/`. Add a dedicated block above your other location rules:

```nginx
location ^~ /.well-known/acme-challenge/ {
    root /var/www/html;
    default_type text/plain;
}
```

The `^~` prefix stops nginx from even looking at regex locations once this prefix matches. Apache users: check that `AllowOverride None` is not blocking the directory, and that no `.htaccess` rule is redirecting HTTP to HTTPS before the token can be served.

---

### I'm behind Cloudflare's proxy. Does HTTP-01 work?

Sometimes. If the SSL mode is "Full" or "Full (Strict)", Cloudflare terminates TLS itself and the challenge file usually gets through. If Always Use HTTPS is enabled, the 80-to-443 redirect fires before the token is ever served.

Easiest fix: switch to DNS-01. Cloudflare is a [supported DNS provider](#cloudflare-1), so it is a one-line handler swap and the orange cloud stays orange.

If you are committed to HTTP-01, grey-cloud the record (DNS only) during issuance, then flip it back. Cloudflare's proxy is not going anywhere, but it can be asked to step aside briefly.

---

### `issueOrRenew()` issues a fresh certificate on every single cron run.

You are missing storage, or the path changes between runs. Without a storage backend, `needsRenewal()` always returns `true` because there is nowhere to check what you already have. Like a dog who has never seen a ball before in its life.

```php
->storage(new FilesystemStorage('/etc/coyotecert'))
```

Same path, every run. If you are using `DatabaseStorage`, confirm the connection points at the same database as last time and not your staging environment.

---

### Can I get a wildcard certificate?

Yes, but DNS-01 only. RFC 8555 forbids wildcard validation over HTTP-01 or TLS-ALPN-01. That is not a CoyoteCert limitation -- it is a rule carved into the RFC the same way the ACME Corporation name was stamped into every box of defective rocket skates.

```php
->identifiers(['*.example.com', 'example.com'])
->challenge(new CloudflareDns01Handler(...))
```

`*.example.com` covers `sub.example.com` but not the apex `example.com`, so include both if you need the root. And `*.*.example.com` is not a thing. The exception message will remind you of this.

---

### I'm getting `CaaException` but my CAA records look fine.

The value compared against your CAA records is the CA's technical identifier, not its product name. ZeroSSL's CAA identifier is `sectigo.com` (or `comodoca.com`), not `zerossl.com`. Google Trust Services is `pki.goog`.

Check the exact identifier for your CA in the [providers section](#certificate-authorities-1), update your CAA record, and the exception disappears. If you are certain the records are correct and just want to skip the pre-check entirely, `->skipCaaCheck()` exists.

---

### Domain validation fails on retry even though the correct TXT record is visible.

A previous failed run may have left a stale `_acme-challenge` TXT record alongside the new one. By default, each DNS-01 handler deletes any pre-existing records before deploying, so this is normally cleaned up automatically. If you are on an older version, or the cleanup was skipped because the process was killed mid-run, you can remove the stale record manually through your DNS provider's dashboard.

If you need to keep existing records for a specific reason, use `->keepExistingRecords()` on the handler.

---

### The CA says `Incorrect TXT record "..." found`, and the value it quotes is the one from my previous run.

The CA read a cached answer. Its validators, including the remote perspectives used for secondary validation, resolve through caching recursors, and a resolver that saw your `_acme-challenge` record during an earlier issuance keeps serving that value for the length of the record's TTL. Re-issuing the same name inside that window fails no matter how cleanly the new value propagated to your authoritative nameservers.

Check the TTL your provider gives the record:

```
dig _acme-challenge.example.com TXT @ns1.your-provider.net
```

If that TTL is the zone default (often 3600 or 86400), that is the problem. CoyoteCert logs a warning when the TTL it observes is longer than the settle delay. Two fixes, both worth doing:

- Create the challenge record with a short TTL. The built-in handlers already use the lowest value each provider accepts (10 for Route53, 30 for DigitalOcean, 60 elsewhere). A custom handler needs to set this itself, otherwise the record inherits the zone default
- Raise `$handler->propagationDelay()` to at least that TTL so the cached answer expires before validation starts

---

### My DNS-01 propagation check times out, but I can see the TXT record in my DNS tool.

Your DNS tool is probably querying a resolver. CoyoteCert queries the authoritative nameservers directly -- the same approach the ACME validator uses when it comes to check. If you are on split-horizon or internal DNS, the public authoritative servers may not have the record at all, and no amount of staring at your DNS dashboard will fix that.

Three ways out:

- `$handler->propagationTimeout(120)` to wait longer before giving up
- `$handler->propagationDelay(60)` to lengthen the settle pause after the check passes
- `$handler->skipPropagationCheck()` if you are confident the record will be there by the time the CA arrives

---

### How do I test without burning Let's Encrypt rate limits?

`LetsEncryptStaging`. The certificates are not browser-trusted but the full ACME handshake is byte-for-byte identical to production. Hammer it as many times as you need.

```php
$coyote = CoyoteCert::provider(new LetsEncryptStaging())
    // ... rest of your config
```

When everything looks good, swap to `LetsEncrypt` and issue once for real. Do not skip staging and go straight to production. Somebody does this every time, and they always end up filing a rate limit issue on GitHub.

---

### What if my account key is stolen?

Revoke every certificate issued under it, then burn the key and start fresh.

```php
$coyote->revoke($storedCert, RevocationReason::KeyCompromise);
```

Delete the old account key files (`account-letsencrypt.pem` and equivalents for other CAs you use), re-run issuance, and CoyoteCert registers a new account automatically. The CA has no long memory for this sort of thing, which is more than can be said for most relationships.

---

### How do I migrate from certbot or acmephp?

Point `FilesystemStorage` at a new directory and let CoyoteCert issue fresh certificates. Account formats are incompatible so there is no import path -- but there is no need for one either. New account, same domains, same webroot. Your existing certificates stay valid until they expire naturally.

If you were using HTTP-01 with a certbot webroot, the `Http01Handler` webroot path is the exact same directory certbot was writing to. CoyoteCert will walk in and take over like it was always there.

---

### I run on multiple servers. Can they share an account?

Yes. Use `DatabaseStorage` with a shared database, or `FilesystemStorage` on a shared volume with consistent paths. File locking is safe across concurrent processes, so two servers racing to `issueOrRenew()` at the same time will not corrupt anything. They will both end up holding the same certificate, which is the civilised outcome.

```php
->storage(new DatabaseStorage($sharedPdo))
```

One account key per CA, shared by however many servers you run.

---

## Maintained by Blendbyte

<br>

<p align="center">
  <a href="https://www.blendbyte.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://www.blendbyte.com/logo_horizontal_light.png">
      <img src="https://www.blendbyte.com/logo_horizontal.png" alt="Blendbyte" width="360">
    </picture>
  </a>
</p>

<p align="center">
  <strong><a href="https://www.blendbyte.com">Blendbyte</a></strong> builds cloud infrastructure, web apps, and developer tools.<br>
  We've been shipping software to production for 20+ years.
</p>

<p align="center">
  This package runs in our own stack, which is why we keep it maintained.<br>
  Issues and PRs get read. Good ones get merged.
</p>

<br>

<p align="center">
  <a href="https://www.blendbyte.com">blendbyte.com</a> · <a href="mailto:hello@blendbyte.com">hello@blendbyte.com</a>
</p>
