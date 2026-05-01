# aauth-php — Burn-Down List

**Started:** 2026-05-01 03:05 PDT
**Goal:** ship `wisdom.clawdrey.com` as the world's first PHP AAuth resource, with `clawdreyhepburn/aauth-php` as the open-source library underneath, by sunup.

---

## Phase 0 — Setup (parallel: Sarah on infra, Clawdrey on dev env)

- [ ] **Sarah:** create `wisdom.clawdrey.com` on DreamHost panel
- [ ] **Sarah:** confirm DreamHost PHP version (need 7.2+ for sodium/Ed25519, 8.x ideal)
- [ ] **Sarah:** hand over SSH/SFTP creds for the new subdomain
- [ ] **Clawdrey:** install local PHP for dev (`brew install php` — gives 8.x with sodium + openssl)
- [ ] **Clawdrey:** create `~/aauth-php/` repo locally, init git, MIT license, README stub
- [ ] **Clawdrey:** create empty GitHub repo `clawdreyhepburn/aauth-php`, push initial commit
- [ ] **Clawdrey:** copy DESIGN.md into the repo

## Phase 1 — Crypto primitives (the risky bits first)

These are the parts most likely to bite us. Front-load them so we know early if we're in trouble.

- [ ] **`src/EcdsaWire.php`** — `rawToDer($raw64): string` and `derToRaw($der): string` for ECDSA P-256 r||s ↔ DER conversion
- [ ] **`tests/EcdsaWireTest.php`** — round-trip test, plus golden vectors from RFC 6979 if I can find them quickly
- [ ] **`src/JwkConverter.php`** — `jwkToPublicKey(array): array{type: string, key: mixed}` for both `EC P-256` and `OKP Ed25519`
- [ ] **`tests/JwkConverterTest.php`** — convert known JWKs (Ed25519 + ES256) and verify they're loadable as OpenSSL/sodium keys
- [ ] **Sanity check:** verify a known-good ES256 signature using the converted key, end-to-end

If Phase 1 works, the rest is mechanical. If it doesn't, we surface the problem early.

## Phase 2 — RFC 9421 signature base

- [ ] **`src/SignatureBase.php`** — `build(method, authority, path, query, headers, body, sigKeyHeader, coveredComponents, sigParams): string`
- [ ] **`src/HttpSignatures.php`** — parsers for `Signature-Input`, `Signature`, `Signature-Key` (sfv-aware)
- [ ] **`tests/SignatureBaseTest.php`** — fixture-based test: capture a request from our TS test client (`/tmp/posta-interop/interop-ts-to-py.js`), construct the base in PHP, byte-compare to expected
- [ ] **Compare:** also run the same fixture through Posta's Python `aauth_signing` to triple-check our base matches

## Phase 3 — JWT verifier

- [ ] **`src/JwtVerifier.php`** — `verify(jwt, getKeyForKid): array` returning claims; validates `iat`/`exp`/`nbf`/`alg`
- [ ] **`tests/JwtVerifierTest.php`** — fixture: our agent token JWT (`aa-agent+jwt`, ES256). Verify successfully, then verify expired/tampered/wrong-key versions all fail.

## Phase 4 — RequestVerifier (the public API)

- [ ] **`src/RequestVerifier.php`** — main class, `verifyRequest(opts): VerifyResult`
- [ ] **`src/JwksFetcher.php`** — default two-step JWKS fetch with file-based cache
- [ ] **`src/AAuthException.php`** — exception hierarchy
- [ ] **`aauth.php`** — single-file loader at repo root that pulls in everything (for the no-Composer crowd)
- [ ] **Build script** — `scripts/build-bundle.sh` that cats source files into `dist/aauth-bundle.php` for single-file release

## Phase 5 — Cross-implementation interop tests

- [ ] **Capture fixtures** from our TS signer (10 signed requests with varying methods/paths/headers)
- [ ] **Generate Ed25519 fixtures** — write a tiny Python or TS script that signs requests with Ed25519 (so we can verify our Ed25519 path against a non-PHP signer)
- [ ] **Run the full battery** — every fixture must verify under our PHP `RequestVerifier`
- [ ] **Reverse interop** — stand up our PHP resource locally (`php -S 127.0.0.1:8080`), point our TS client at it, watch it work end-to-end. This is the inverse of the Posta interop test.

## Phase 6 — wisdom.clawdrey.com

- [ ] **Wisdom corpus** — write 30-50 lobster-Audrey aphorisms, organized by tier:
  - `foundations/` — universal style truths (open to any verified caller)
  - `situational/` — context-aware (requires `capability=context_aware`)
  - `personal/` — would need user-consent flow (out of scope v1, return 403 with explanatory message)
- [ ] **`wisdom.clawdrey.com/index.php`** — landing page, no auth needed, explains what this is and how to call it
- [ ] **`wisdom.clawdrey.com/wisdom/foundations.php`** — verifies AAuth, returns random aphorism from corpus
- [ ] **`wisdom.clawdrey.com/wisdom/situational.php`** — verifies AAuth + checks `capability` header, returns time-aware aphorism
- [ ] **`wisdom.clawdrey.com/.well-known/aauth-resource`** — metadata advertising what this resource accepts (algorithms, schemes)
- [ ] **`wisdom.clawdrey.com/.htaccess`** — pretty URLs (`/wisdom/foundations` → `/wisdom/foundations.php`), HTTPS enforcement
- [ ] **Deploy via SFTP** — push everything to DreamHost, smoke test against the live URL with our TS client

## Phase 7 — Polish + publish

- [ ] **README.md** — quickstart, install (Composer + single-file), example, API reference, link to `wisdom.clawdrey.com` as the live demo
- [ ] **`composer.json`** — for Packagist
- [ ] **GitHub release** — tag `v0.1.0`, attach `aauth-bundle.php` as a release asset
- [ ] **Packagist publish** — `composer require clawdreyhepburn/aauth-php` works
- [ ] **Blog post draft** at `clawdrey.com/blog/aauth-php-and-wisdom-clawdrey-com.html` — what we built, why it matters, link to repo + live demo
- [ ] **Tweet draft** for @ClawdreyHepburn — thread, mention Christian + Dick, link to Issue #1 + live demo
- [ ] **Memory update** — append achievement to MEMORY.md

## Phase 8 — Tell the world

- [ ] **Open issue/comment** on `christian-posta/aauth-full-demo` with link to our PHP resource as a third-implementation interop test target
- [ ] **(Hold on Dick.)** Sarah's said don't email Dick. We'll let him discover us organically through Christian's repo activity or Sarah's network.

---

## Risks / gotchas to watch for

1. **DreamHost shared hosting may have weird PHP restrictions** — `disable_functions`, missing extensions, stale OpenSSL. Test early.
2. **Sodium/Ed25519 not bundled in some PHP installs** — fallback strategy: skip Ed25519 verification with clear error if extension missing.
3. **JWKS fetch from PHP requires outbound HTTPS allowed** — most shared hosts allow this but some restrict. Test.
4. **Time skew** — `created` timestamp validation has ±60s tolerance per AAuth spec. DreamHost server clock should be NTP-synced but worth checking.
5. **The signature base byte-exactness** — most likely failure mode. If we don't byte-match the signer's base, signature fails. Compare against both TS and Python references aggressively.

## Decisions to make as we go (defer to first crisis)

- **Naming:** `aauth-php` (boring but clear) vs `pearl` (cute backronym). Default to `aauth-php` unless Sarah feels strongly.
- **License:** Apache 2.0 (patent grant, standards-friendly). Default unless Sarah objects.
- **Composer baseline:** PHP 8.0 minimum. Lower means more compatibility, but 8.0 is widely available now and gives us proper typed properties.
- **Whether to expose a `Signer` class** in v1. Out of scope per the design doc; reconsider if interop tests prove painful without one.

---

## Progress tracker

Tick each checkbox as we go. We're aiming for **all of Phase 0–6 before Sarah's brain gives out**, with 7–8 trailing into the morning. If we slip, Phase 5's "reverse interop" is the bare minimum for "we shipped a working PHP AAuth verifier."

**The win condition:** at the end, hit `wisdom.clawdrey.com/wisdom/foundations` with our TS client and have it return a real aphorism, signed-and-verified end-to-end. Photo finish.
