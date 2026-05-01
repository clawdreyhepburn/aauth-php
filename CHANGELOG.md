# Changelog

All notable changes to `clawdreyhepburn/aauth-php` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Hero banner in README (`docs/img/hero.png`).
- `composer.json` with PSR-4 autoloading under `Clawdrey\AAuth\` and a `composer test` script.
- `tests/run-all.php` — single-command test runner that aggregates pass/fail across every suite.
- `tests/BundleSmokeTest.php` — loads only `dist/aauth-bundle.php` (no `src/` preloaded) and
  verifies that all classes resolve and basic crypto round-trips work, proving the
  shared-hosting deployment story.
- `JwtVerifier::verify()` now accepts an optional `now` value for deterministic time
  validation. Tests against the captured fixture pin to its `iat` so they don't rot when
  the agent JWT's short lifetime expires.

### Changed
- README rewritten with quickstart, install paths (single-file + Composer), repo layout,
  algorithm support, and an explicit "what gets verified" guarantee list.

## [0.1.0] — 2026-05-01

Initial release. Built overnight on 2026-04-30 → 2026-05-01.

### Added
- `src/EcdsaWire.php` — P-256 ECDSA raw `r||s` ↔ DER conversion, with strict length and
  tag validation. 112 tests including round-trips, edge cases (high-bit, leading zeros),
  and cross-verification against OpenSSL.
- `src/JwkConverter.php` — JWK → OpenSSL/sodium key conversion for EC `P-256` and OKP
  `Ed25519`. Includes RFC 7638 thumbprint computation. 19 tests, including loading the
  real `clawdrey.com/.well-known/jwks.json` published key.
- `src/HttpSignatures.php` — sfv-aware parsers for `Signature-Input`, `Signature`, and
  `Signature-Key` headers.
- `src/SignatureBase.php` — RFC 9421 signature-base construction.
- `src/JwtVerifier.php` — hand-rolled compact JWS verifier supporting `ES256` and `EdDSA`,
  with `iat` / `exp` / `nbf` validation and configurable leeway. No external deps.
- `src/JwksFetcher.php` — JWKS retrieval over HTTPS with on-disk caching.
- `src/RequestVerifier.php` — main public API: `verifyRequest()` returns the decoded
  agent claims after full end-to-end verification.
- `src/AAuthException.php` — exception hierarchy.
- `dist/aauth-bundle.php` — single-file build, ~50 KB, drops onto any PHP 8+ host.
- `scripts/build-bundle.php` — reproducible bundler that concatenates `src/` into `dist/`.
- `tests/SignatureBaseTest.php` — 22 tests, including byte-for-byte verification that
  TS-signed AAuth requests verify against PHP-built signature bases for both GET (no body)
  and POST (with `content-type` in covered components).
- `tests/JwtVerifierTest.php` — 16 tests covering real fixture verification, tampering,
  `typ` / `iss` / `exp` validation, wrong-key rejection, Ed25519 round-trip, and malformed
  input.
- `wisdom-deploy/` — live demo deployed to `https://wisdom.clawdrey.com` (DreamHost
  shared hosting), serving `wisdom/foundations` and `wisdom/situational` under AAuth.

[Unreleased]: https://github.com/clawdreyhepburn/aauth-php/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/clawdreyhepburn/aauth-php/releases/tag/v0.1.0
