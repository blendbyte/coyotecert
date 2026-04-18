<img alt="coyotecert-banner-2560x1706" src="https://github.com/user-attachments/assets/d5510075-b62c-462f-a941-1d31b48bbec3" />

# CoyoteCert

[![Latest Version on Packagist](https://img.shields.io/packagist/v/blendbyte/coyotecert.svg?style=flat-square)](https://packagist.org/packages/blendbyte/coyotecert)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://github.com/blendbyte/coyotecert/blob/main/LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-787cb5?style=flat-square)](https://www.php.net)
[![Tests](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/tests.yml?branch=main&style=flat-square&label=tests)](https://github.com/blendbyte/coyotecert/actions/workflows/tests.yml)
[![Static Analysis](https://img.shields.io/github/actions/workflow/status/blendbyte/coyotecert/static-analysis.yml?branch=main&style=flat-square&label=phpstan)](https://github.com/blendbyte/coyotecert/actions/workflows/static-analysis.yml)
[![Coverage](https://img.shields.io/codecov/c/github/blendbyte/coyotecert?style=flat-square)](https://codecov.io/gh/blendbyte/coyotecert)

**A PHP 8.3+ ACME v2 client for issuing, renewing, and revoking TLS certificates.** Works with Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, Buypass, and any RFC 8555-compliant CA. Fluent API, no framework dependencies, solid test coverage.

ACME (Automatic Certificate Management Environment) is the protocol behind free, automated TLS certificates. Yes, same name as the cartoon supply company. We leaned into it. CoyoteCert covers the whole thing: account management, order lifecycle, HTTP-01, DNS-01, and TLS-ALPN-01 challenges, certificate issuance, ARI smart renewal, and revocation. One `composer require blendbyte/coyotecert` and you're running.

---

## Why CoyoteCert

### Every major CA, out of the box

Built-in providers for Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, and Buypass, full EAB support included, and ZeroSSL auto-provisions credentials from your API key so no token copy-pasting. Anything more exotic? `CustomProvider` handles any RFC 8555-compliant CA.

### A CLI that ships with the package

`coyote issue` and `coyote status` come in the box. Issue a certificate with one command, check what you've got with another. Drop it in wherever certbot or acme.sh would go in a PHP stack: same providers, same key types, same storage paths, cron-friendly exit codes.

### Storage that fits wherever you are

Filesystem with file locking, PDO for MySQL/PostgreSQL/SQLite, and in-memory for tests. All three share the same interface, so switching backends never touches your issuance code.

### Six DNS-01 providers, no extra SDK needed

Cloudflare, Hetzner DNS, DigitalOcean, ClouDNS, AWS Route53, and shell/exec, all with automatic zone detection, post-deploy propagation checking, and a fluent API for tuning timeouts. Route53 handles SigV4 signing itself; no AWS SDK required. Wildcards need DNS-01, and CoyoteCert has the providers covered.

### dns-persist-01: skip the propagation wait every renewal cycle

Deploy the TXT record once, leave it there. Every subsequent renewal validates against the same record with no propagation wait. No DNS dance every 90 days.

### Fails fast, before it costs you

CoyoteCert checks CAA DNS records for every domain before touching the CA. If a record blocks your chosen CA, you get a `CaaException` immediately, not after burning a rate-limit attempt. Same pre-flight logic verifies your HTTP token or DNS TXT record locally before the CA comes knocking.

### Typed exceptions that tell you what actually went wrong

`RateLimitException` carries the CA's `Retry-After` seconds so your retry logic is precise. `AuthException` means bad credentials, not a transient blip. `AcmeException::getSubproblems()` tells you exactly which domain in a multi-domain order was rejected and why.

### Short-lived certificates and ACME profiles

Let's Encrypt's `shortlived` profile gives you 6-day certs with no OCSP or CRL overhead. CoyoteCert passes the profile through and quietly ignores it on CAs that haven't caught up yet. Call `->profile()` unconditionally.

### RFC 8555 + RFC 9773, done right

Proper nonce handling with automatic retry on `badNonce`, JWS signing for every request, EAB for CAs that require it, and ARI (RFC 9773) so renewal windows are set by the CA rather than a fixed calendar guess.

### No default CA, no hidden opinions

CoyoteCert has no default CA. Every call requires an explicit provider. Trust store coverage, rate limits, certificate lifetime, EAB requirements, data residency. Those trade-offs are yours to make, not ours.

### Also worth knowing

**ECDSA-first:** keys default to EC P-256; EC P-384, RSA-2048, and RSA-4096 are all there.

**IP address certificates** (RFC 8738): pass an IP to `->identifiers()` and it works. `type: ip` on the order, `IP:` SANs in the CSR, no extra setup.

**PSR-18 HTTP client:** the built-in curl client needs no extra dependencies; swap it for any PSR-18 client with one builder call.

**94%+ test coverage:** unit tests with mocked responses plus a live [Pebble](https://github.com/letsencrypt/pebble) integration suite across PHP 8.3, 8.4, and 8.5. No mock-only false confidence.

**Modern PHP:** strict types, backed enums, readonly constructor promotion. No magic methods, no global state.

**Truly independent:** no CA affiliation, not maintained or financed by one.

---

## Requirements

PHP ^8.3 with `ext-curl`, `ext-json`, `ext-mbstring`, and `ext-openssl`.

---

## Installation

```bash
composer require blendbyte/coyotecert
```

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

## CLI

CoyoteCert ships with a `coyote` CLI for issuing and inspecting certificates without writing PHP. It wraps the same builder API as the library.

### Install globally

```bash
composer global require blendbyte/coyotecert
```

Make sure `~/.composer/vendor/bin` (or `~/.config/composer/vendor/bin` on Linux) is on your `PATH`.

### `coyote issue`

Issue or renew a certificate using HTTP-01 or DNS-01 challenge validation.

**HTTP-01** write a token file to your web root:

```bash
coyote issue \
  --identifier example.com \
  --identifier www.example.com \
  --webroot /var/www/html \
  --email admin@example.com \
  --provider letsencrypt \
  --storage /etc/certs
```

**DNS-01** create a TXT record via a DNS provider (required for wildcards). Set the provider's credentials as environment variables, then pass `--dns`:

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
| `--dns-propagation-delay` | | `0` | Fixed delay in seconds after the propagation check, for providers with slow secondary sync |
| `--dns-skip-propagation` | | | Skip the post-deploy DNS propagation check entirely (split-horizon or internal DNS) |
| `--provider` | `-p` | | CA to use. See provider table below. **Required** |
| `--storage` | `-s` | `./certs` | Directory to read/write certificates and account keys |
| `--days` | | `30` | Renew when fewer than this many days remain before expiry |
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

### Cron renewal

Add a daily cron job to keep certificates renewed automatically:

```
0 3 * * * coyote issue --identifier example.com --webroot /var/www/html --storage /etc/certs --email admin@example.com
```

The command is idempotent: it does nothing until fewer than `--days` (default 30) remain, so running it daily is safe.

### Help and version

```bash
coyote --help         # list available commands
coyote --version      # show version
coyote issue --help   # full option reference for issue
coyote status --help  # full option reference for status
```

---


## Providers

CoyoteCert ships with built-in providers for every major public ACME CA. Pick one and go.

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

The classic. Production for real certs, staging for development. No rate limits on staging, but certificates aren't browser-trusted.

```php
use CoyoteCert\Provider\LetsEncrypt;
use CoyoteCert\Provider\LetsEncryptStaging;

CoyoteCert::with(new LetsEncrypt())
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
CoyoteCert::with(new BuypassGoStaging())
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

---

## Challenge handlers

ACME requires you to prove domain ownership by completing a challenge. CoyoteCert ships with an HTTP-01 handler and abstract bases for DNS-persist-01 and TLS-ALPN-01. DNS-01 is implemented via the `ChallengeHandlerInterface`.

### http-01

The simplest challenge. CoyoteCert writes a token file to your web root; the CA fetches it over HTTP to confirm you control the domain.

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

### dns-persist-01

A CoyoteCert-specific strategy: deploy the TXT record once and leave it permanently. Every renewal validates against the same record with no propagation wait and no deploy/cleanup cycle.

Extend `DnsPersist01Handler` and implement `deploy()`. The `cleanup()` method is a no-op by design.

```php
use CoyoteCert\Challenge\DnsPersist01Handler;

class Route53DnsPersist01Handler extends DnsPersist01Handler
{
    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        // The key auth value changes on every order, so always upsert.
        Route53::upsertTxtRecord('_acme-challenge.' . $domain, $keyAuthorization);
    }
}
```

```php
->challenge(new Route53DnsPersist01Handler())
```

> **Note:** The TXT record value (`$keyAuthorization`) changes on every order, even with dns-persist-01. Your `deploy()` must update (upsert) the record every time.

### tls-alpn-01

Defined in [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737). The CA opens a TLS connection to port 443, negotiates `acme-tls/1`, and expects a self-signed certificate with a critical `id-pe-acmeIdentifier` extension containing the SHA-256 digest of the key authorization. No port 80 required.

Extend `TlsAlpn01Handler`, implement `deploy()` and `cleanup()`, and call `generateAcmeCertificate()` to get the RFC 8737-encoded cert and key, no manual DER encoding needed.

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

Six built-in DNS-01 handlers, all extending `AbstractDns01Handler`, which runs a post-deploy propagation check by default. Three fluent controls let you tune the behaviour:

```php
// All return a new immutable instance.
$handler->propagationTimeout(120)    // seconds to poll for the TXT record (default: 60)
$handler->propagationDelay(10)       // fixed pause after the check, for slow secondaries (default: 0)
$handler->skipPropagationCheck()     // skip polling entirely (split-horizon / internal DNS)
```

Zone detection is automatic: the handler walks public-suffix candidates (`sub.example.com` → `example.com`) until it finds a match in the API. Supply an explicit zone to skip the detection call entirely.

### Cloudflare

Needs an API token with `Zone.DNS:Edit` permission.

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

Needs an API token from the [Hetzner DNS Console](https://dns.hetzner.com).

```php
use CoyoteCert\Challenge\Dns\HetznerDns01Handler;

$handler = new HetznerDns01Handler(apiToken: 'your-api-token');

// With explicit zone ID
$handler = new HetznerDns01Handler(apiToken: 'your-api-token', zoneId: 'zone-id');
```

### DigitalOcean

Needs a personal access token with write access to domains.

```php
use CoyoteCert\Challenge\Dns\DigitalOceanDns01Handler;

$handler = new DigitalOceanDns01Handler(apiToken: 'your-api-token');

// With explicit zone name
$handler = new DigitalOceanDns01Handler(apiToken: 'your-api-token', zone: 'example.com');
```

### ClouDNS

Needs a ClouDNS auth-id and auth-password from your account panel.

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

Storage persists the ACME account key and issued certificates between runs. Without it, CoyoteCert issues a fresh certificate and creates a new ACME account every time, which is probably not what you want.

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

The one you want in production. Returns the existing certificate if it's still valid; issues a new one when it's getting close to expiry. Accepts an optional `$daysBeforeExpiry` threshold (default 30).

```php
$cert = CoyoteCert::with(new LetsEncrypt())
    ->storage(new FilesystemStorage('/var/certs'))
    ->identifiers('example.com')
    ->email('admin@example.com')
    ->challenge(new Http01Handler('/var/www/html'))
    ->issueOrRenew(daysBeforeExpiry: 30);
```

Safe to call as often as you like. It does nothing when the certificate is still healthy. Run it in a cron job and forget about it.

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

- no storage is configured
- no certificate is stored for the primary domain
- the stored certificate expires within `$daysBeforeExpiry` days
- an ARI renewal window is open (see [ARI](#ari-ca-guided-renewal-windows))

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

[CAA (Certification Authority Authorization)](https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization) records let a domain owner restrict which CAs can issue for them. If `example.com` has `CAA 0 issue "digicert.com"`, Let's Encrypt will reject the order, but only after you've consumed a rate-limit attempt and sat through the ACME workflow.

CoyoteCert checks CAA itself before talking to the CA. If the records block your chosen CA, you get a `CaaException` right away:

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

`CaaException` extends `AcmeException`, so existing catch blocks for the base type keep working.

IP address identifiers are excluded; CAA records apply to domain names only.

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

`AuthException` is thrown on 401 and 403 responses. Distinct from a rate limit or a transient server error, so you can alert or re-provision credentials rather than retrying blindly.

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

Pass an array of domains to `->identifiers()`. Wildcards need DNS-01 or dns-persist-01.

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

The recommended setup: a scheduled cron job calling `issueOrRenew()`.

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

Add to crontab. Daily is fine; `issueOrRenew()` does nothing until renewal is actually due:

```
0 3 * * * php /usr/local/bin/renew-certs.php
```

---

## ARI: CA-guided renewal windows

[RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) lets a CA tell you exactly when it wants you to renew: a specific window, not just "X days before expiry." CoyoteCert checks the ARI endpoint automatically whenever `needsRenewal()` or `issueOrRenew()` is called.

- If the CA exposes a `renewalInfo` URL and the window is open, `needsRenewal()` returns `true` even if the certificate has more than `$daysBeforeExpiry` days left.
- If the ARI request fails, CoyoteCert falls back to the `$daysBeforeExpiry` threshold silently.
- If the CA doesn't support ARI, the threshold is used exclusively.

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

Use `->preferredChain()` to request a chain by matching against the Common Name or Organisation of the intermediate certificates. The match is a case-insensitive substring, so partial names work fine. If no alternate chain matches, CoyoteCert falls back to the default chain, always safe to include.

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

Returns `true` on success, `false` if the CA rejected the request.

After revoking, delete the stored certificate so `issueOrRenew()` requests a fresh one:

```php
$storage->deleteCertificate('example.com', KeyType::EC_P256);
```

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

`StoredCertificate` is the value object returned by `issue()`, `issueOrRenew()`, and `renew()`. It holds all certificate data and exposes a handful of inspection helpers.

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
| `->preferredChain(string)` | fluent | `''` | Preferred chain issuer CN/O (RFC 8555 §7.4.2); falls back to default if no match |
| `->skipLocalTest()` | fluent | off | Disable pre-flight HTTP/DNS self-check |
| `->skipCaaCheck()` | fluent | off | Disable CAA DNS pre-check |
| `->onIssued(callable)` | fluent | none | Callback fired after every successful issuance; receives `StoredCertificate` |
| `->onRenewed(callable)` | fluent | none | Callback fired when an existing cert is replaced; receives `StoredCertificate` |
| `->issue()` | terminal | | Issue unconditionally; returns `StoredCertificate` |
| `->renew()` | terminal | | Alias for `issue()` |
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
$window = $api->renewalInfo()->get($certPem, $issuerPem);
$certId = $api->renewalInfo()->certId($certPem, $issuerPem);

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
