# Security

## Reporting a vulnerability

If you find a security issue in `aauth-php`, please report it privately so we
can fix it before public disclosure:

- **GitHub:** open a [private security advisory](https://github.com/clawdreyhepburn/aauth-php/security/advisories/new) — preferred channel

Please **do not** file a public GitHub issue for security problems.

I'll acknowledge within 72 hours and aim to ship a fix or mitigation within
two weeks for high-severity issues. If you want, I'll credit you in the
release notes once the fix is out.

## What's in scope

This is a verifier library; the threat model is "an attacker controls the HTTP
request and tries to make the verifier accept it." Things in scope:

- Bypass of signature verification, JWT verification, or replay-window checks
- Algorithm confusion (e.g., tricking ES256 verification into accepting EdDSA)
- Signature-base construction errors that let an attacker silently strip
  components covered by `Signature-Input`
- Cache-poisoning paths in `JwksFetcher` (path traversal, mixing keys across
  origins, accepting non-HTTPS JWKS endpoints, etc.)
- Time-of-check / time-of-use bugs around `created` / `iat` / `exp`
- Memory-safety issues in the binary parsing paths (DER, base64url)
- Timing side channels in any byte-comparison path. The cryptographic
  primitives we rely on (`openssl_verify` for ES256 and
  `sodium_crypto_sign_verify_detached` for EdDSA) are themselves
  constant-time; if you find a hand-rolled comparison of secret material
  that isn't, that's a bug.

## What's out of scope

- Vulnerabilities in PHP itself or in the `openssl` / `sodium` extensions
- Vulnerabilities in caller-supplied JWKS endpoints or the agent's signing
  process — the verifier's job is to reject bad input, not to fix it upstream
- Denial of service via large headers, slow JWKS endpoints, or oversized JWTs.
  We do enforce reasonable limits, but a full DoS-hardening pass is the
  caller's job.

## Algorithm policy

`aauth-php` only accepts the algorithms the AAuth specification permits:

- **`ES256`** (ECDSA P-256, SHA-256) — required
- **`EdDSA`** (Ed25519) — required

`alg: none` is rejected. RSA is intentionally not supported, in line with the
AAuth specification's choice to keep the algorithm matrix small. Adding new
algorithms requires explicit changes to `JwtVerifier::verifySignature` and
`JwkConverter::jwkToPublicKey`; there is no extensibility mechanism a caller
can use to opt back into a removed algorithm. This is by design.

## Defaults that matter

These defaults are chosen for safety; you can tighten them, but you cannot
loosen them in a way that violates AAuth:

- **JWT leeway:** 60 seconds (configurable via `verify($jwt, $resolver, ['leeway' => N])`)
- **Replay window on `created`:** ±60 seconds (configurable via
  `new RequestVerifier(['created_leeway' => N])`)
- **JWKS cache TTL:** 1 hour (configurable on `JwksFetcher`)
- **JWKS HTTPS-only:** the fetcher refuses non-HTTPS JWKS URIs by default.
  Tests and local fixtures can opt back into `http://` with
  `new JwksFetcher(['allow_insecure_scheme' => true])`. Even with the
  opt-in, only `http://` is permitted — `file://`, `ftp://`,
  `javascript:`, and friends are always rejected.

## Supported versions

Until v1.0, only the latest minor receives security fixes. After v1.0 I'll
maintain the previous minor for at least 6 months past the next release.

## Known weak spots / future work

These are documented honestly so callers can make informed decisions.
None of them are exploitable as of v0.1, but they're places I'd look first:

- The signature-base parser uses targeted regex rather than a full
  Structured-Field-Values parser. It works for every fixture from the
  TypeScript and Python reference implementations, but a malicious signer
  could theoretically craft a header that we parse one way and the spec
  parses another. If you find such a case, please report it.
- `JwksFetcher` uses curl with a 5-second connect / 10-second total timeout.
  A slow JWKS endpoint can therefore stall a request handler for up to 10s.
  Consider running with an out-of-band cache warmer for high-traffic deploys.
- The on-disk JWKS cache assumes the cache directory is writable only by the
  application user. If you point it at a shared `/tmp`, an attacker on the
  same host could substitute keys.
