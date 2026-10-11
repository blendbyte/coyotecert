# Upgrading

## From 1.x to 2.0

2.0 fixes a number of protocol bugs, and some fixes change behaviour. Most applications that use the `CoyoteCert` builder only need the first section. The low-level API and CLI changes matter if you call `Api`, the endpoints or `coyote` directly.

### Behaviour changes in the builder

- **Renewal timing.** `needsRenewal()` and `issueOrRenew()` no longer default to "30 days before expiry". When the CA offers ARI, its renewal window decides (and a window that has already passed now means "renew now"). Otherwise renewal is due once a third of the certificate's lifetime remains. Pass `$daysBeforeExpiry` to keep a fixed threshold.
- **Renewal on changed identifiers.** A stored certificate that doesn't cover every configured identifier, has expired or can't be parsed is renewed.
- **Identifiers are lower-cased.** Certificates stored under a mixed-case primary domain by 1.x are not found and get reissued once.
- **Profiles are checked.** A profile the CA doesn't list in its directory throws an `AcmeException` instead of being silently dropped.
- **Wildcards need dns-01.** A wildcard identifier with a handler that can't do dns-01 throws before any request is made.
- **Preferred chain.** `preferredChain()` now matches the issuer of the chain's topmost certificate exactly (case-insensitive), like certbot's `--preferred-chain`. Partial names such as `'X1'` no longer match.
- **Account contact.** `email()` is now sent to the CA as the account contact.
- **No storage.** `issue()` without `storage()` works (it registers a new ACME account on every call).

### Removed providers

- `BuypassGo` and `BuypassGoStaging`: Buypass ended its ACME service in April 2026.

### DNS-01 handlers

- **Hetzner** now uses the Hetzner Cloud API. Create a Cloud API token in the Hetzner Console; tokens from the old DNS Console no longer work. An explicit `zoneId` is the Cloud zone ID.
- **Shell:** the cleanup command now runs once per deployed value with `{keyauth}` / `ACME_KEYAUTH` set, and commands are stopped after `timeout` seconds (default 120).
- **SSL.com:** EAB credentials are optional (`new SslCom()` works), since its directories don't require them.

### Low-level API

- `RenewalInfo::get()` and `certId()` take only the certificate PEM. The cert ID follows RFC 9773 (AKI key identifier plus serial); 1.x computed an ID real CAs reject.
- `RenewalWindow::isOpen()` is true from the window start onward, including after the window has ended.
- `Certificate::revoke()` takes a `RevocationReason` instead of an int.
- `Http\Client` throws an `AcmeException` with the curl error on transport failures instead of returning a synthetic 504 response, and never resends a POST.
- `DomainValidation::status()` and `allChallengesPassed()` throw when an authorization can't be fetched.
- `Order::refresh()` and `waitUntilValid()` throw on error responses.
- `OrderData::$expires` and `DomainValidationData::$expires` are nullable; `OrderData` and `Response` are readonly classes.
- `CertificateBundleData::$fullchain` contains the leaf when the CA returns no chain (was empty).
- `DomainValidationException::challengeInvalid()` reports subproblems in the RFC 8555 shape (`type`, `detail`, `identifier`).
- `Api::accountAdapter()` returns `StorageAccountAdapter`.

Removed:

- `Support\LocalFileAccount`, `Interfaces\AcmeAccountInterface`, `Support\CryptRSA`, `Support\Thumbprint` (use `JsonWebKey::thumbprint(JsonWebKey::compute($pem))`), and the global `CoyoteCert\Support\value()` helper
- `Exceptions\OrderNotFoundException`, `Order::get()`, `Directory::getOrder()`
- `OrderData::withCertificateUrl()`, `withFinalized()`, `isFinalized()`, `isNotFinalized()` and the `finalized` property
- `Arr::first()`, `Response::isJson()`, `Response::hasBody()`, `EcSigning::ecParamsFromKey()`
- `StorageAccountAdapter::generateNewKeys()`, `getPublicKey()` and its `keyType` constructor argument

### Storage

- `DatabaseStorage::createTableSql()` takes the PDO driver as a second argument (`mysql` by default) and now generates working SQL for PostgreSQL and SQLite. Existing tables keep working.
- `FilesystemStorage` writes every file except the public certificate and chain PEMs with mode 0600, including `cert.json`.

### CLI

- Errors go to stderr. Usage errors exit with `2`; `coyote status` exits with `1` when the certificate is missing or expired.
- `coyote revoke` no longer accepts `--zerossl-key`, `--eab-kid` or `--eab-hmac` (revocation doesn't need them).
- `--key-type` on `status` and `revoke` defaults to any stored key type.
- `--days` has no default; the renewal rule above applies.
- The ZeroSSL key and EAB credentials can come from `ZEROSSL_API_KEY`, `ACME_EAB_KID` and `ACME_EAB_HMAC`.
- `nunomaduro/termwind` is no longer a dependency.

### Requirements

- `ext-mbstring` is no longer required.
