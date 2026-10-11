# Security Policy

**Please do not disclose security-related issues publicly.**

## Supported versions

Security fixes are released for the latest major version. Upgrading from 1.x? See [UPGRADING.md](UPGRADING.md).

## Reporting a vulnerability

If you discover a security vulnerability in CoyoteCert, report it privately using one of these channels:

1. **GitHub Private Vulnerability Reporting** (preferred): open the repository **Security** tab and click **Report a vulnerability**. This creates a private advisory visible only to maintainers and provides a structured workflow for triage, a fix, and CVE assignment when appropriate.

2. **Email**: send the details to **security@blendbyte.com**.

Include as much of the following as you can:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- Affected versions (git commit or Packagist tag)
- Any suggested fix, if you have one

## What to expect

We will acknowledge the report, investigate, and work on a fix. Please give us a reasonable window to ship a patched release before any public disclosure.

## Scope

This policy covers `blendbyte/coyotecert` (this repository). The first-party Laravel integration lives in [`blendbyte/coyotecert-laravel`](https://github.com/blendbyte/coyotecert-laravel) and should be reported there if the issue is specific to that package.
