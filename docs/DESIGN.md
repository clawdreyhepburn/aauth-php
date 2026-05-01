# aauth-php — PHP implementation of AAuth resource verification

**Status:** Design v1 (2026-05-01, 3am)
**Author:** Clawdrey
**Why now:** Sarah and I just did a TS↔Python interop test of the AAuth spec. The two existing implementations (Dick Hardt's `@aauth/*` TypeScript suite and Christian Posta's `aauth==0.3.3` Python lib) both target server-side runtimes — Node and Python services. Neither helps the long tail of the web: PHP-on-shared-hosting. That's WordPress, Drupal, every blog, every small-business site, our own `clawdrey.com`. If AAuth wants to be a *web-scale* identity layer for AI agents, it needs a credible PHP story. There isn't one.

## Goals

1. **A PHP library a non-expert can drop into Apache + PHP shared hosting** to verify incoming AAuth-signed requests. No Composer required (because shared hosting users are often on hosts that don't allow shell access, much less `composer install`). Single-file include if we can manage it; small folder of files otherwise.

2. **Spec-correct verification of the wire format** — RFC 9421 signature verification with `ecdsa-p256-sha256` and `ed25519`, plus the AAuth-specific `Signature-Key` header schemes (`jwt`, `jwks_uri`, `hwk`).

3. **Use it ourselves.** Ship `wisdom.clawdrey.com` as the first real-world resource backed by aauth-php. This is both dogfood and demo.

## Non-goals (v1)

- Signing outbound requests. PHP isn't a great place to be an AAuth *agent* (no long-lived process to manage keys), and the existing TS/Python clients cover that. We focus on the verify side.
- The `x509` scheme. The Python lib doesn't implement it either; it's a future spec extension.
- The `auth-server`/three-party flow. Resources verifying agent identity is enough for v1; the consent dance is out of scope.
- HSM/Secure Enclave key storage. PHP shared hosting can't access hardware keys anyway. Resources don't need to sign things, only verify.

## Comparable implementations

- **TypeScript:** `aauth-dev/packages-js` — `@aauth/mcp-resource` is the analog of what we're building. Reads headers, verifies, returns claims.
- **Python:** `christian-posta/aauth==0.3.3` — `aauth.RequestVerifier` class. Exactly what I just used in the interop test. (Side note: it has the Ed25519-only bug for `cnf.jwk` extraction. We'll do better — support both ES256 and Ed25519 from day one.)

So shape-wise we're cloning Posta's `RequestVerifier` API, fixed-and-improved.

## Public API sketch

```php
<?php
require_once 'aauth.php';

use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

$verifier = new RequestVerifier([
    'canonical_authorities' => ['wisdom.clawdrey.com'],
    'jwks_fetcher' => function ($id, $dwk, $kid) {
        // two-step: fetch {id}/.well-known/{dwk}, extract jwks_uri, fetch it
        $meta = json_decode(file_get_contents("{$id}/.well-known/{$dwk}"), true);
        return json_decode(file_get_contents($meta['jwks_uri']), true);
    },
    'cache_dir' => '/tmp/aauth-jwks-cache',  // optional
]);

try {
    $result = $verifier->verifyRequest([
        'method'  => $_SERVER['REQUEST_METHOD'],
        'uri'     => $_SERVER['REQUEST_URI'],
        'headers' => getallheaders(),
        'body'    => file_get_contents('php://input'),
        'require_identity' => true,
    ]);
    // $result contains: agent (sub), agent_id, kid, jkt, raw_jwt_claims, capabilities, mission
    header('Content-Type: application/json');
    echo json_encode([
        'verified' => true,
        'agent' => $result->agent,
        'wisdom' => 'A cat-eye sunglass should never compete with the cocktail. It is a chorus, not a solo.',
    ]);
} catch (AAuthException $e) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => $e->getMessage()]);
}
```

That's the whole user-facing surface for v1. One class, one method, structured exceptions.

## Internal layering

```
aauth.php (loader, exports public API)
├── src/
│   ├── RequestVerifier.php     - the public class
│   ├── SignatureBase.php       - RFC 9421 signature base construction
│   ├── HttpSignatures.php      - parse Signature-Input, Signature, Signature-Key
│   ├── JwksFetcher.php         - default two-step JWKS fetcher with cache
│   ├── JwkConverter.php        - JWK → OpenSSL key resource, polymorphic over EC P-256 and Ed25519
│   ├── EcdsaWire.php           - r||s ↔ DER conversion (the bug Posta has)
│   ├── JwtVerifier.php         - JWT parse + verify (PyJWT/jose-php equivalent, hand-rolled)
│   └── AAuthException.php      - exception hierarchy
└── tests/
    ├── fixtures/               - canned signed requests from TS & Python signers
    └── verify_test.php         - phpunit-free single-file test runner
```

Keeping it ~1000 LOC total. Hand-rolling JWT and signature-base parsing because every PHP JWT library out there pulls in 5+ Composer dependencies, which kills the "drop into shared hosting" story.

## Critical implementation details

These are the spots where I expect to spend most of my time and where past implementations have had bugs.

### 1. ECDSA signature wire encoding

RFC 9421 §3.3.1 specifies raw `r || s` (64 bytes for P-256). PHP's `openssl_verify()` wants DER. So we need a small `r||s → DER` conversion:

```php
function ecdsaRawToDer(string $raw): string {
    if (strlen($raw) !== 64) throw new \Exception('expected 64 bytes for P-256');
    $r = substr($raw, 0, 32);
    $s = substr($raw, 32, 32);
    // strip leading zeros, but ensure high bit isn't set (ASN.1 INTEGER is signed)
    $r = ltrim($r, "\x00");
    if (ord($r[0] ?? "\x00") & 0x80) $r = "\x00" . $r;
    $s = ltrim($s, "\x00");
    if (ord($s[0] ?? "\x00") & 0x80) $s = "\x00" . $s;
    $rPart = "\x02" . chr(strlen($r)) . $r;
    $sPart = "\x02" . chr(strlen($s)) . $s;
    return "\x30" . chr(strlen($rPart) + strlen($sPart)) . $rPart . $sPart;
}
```

This is the bug that bit Posta — a one-way conversion both ways is needed for full ECDSA support.

### 2. Ed25519 in PHP

PHP 7.2+ ships `sodium_crypto_sign_verify_detached()` natively. For DreamHost's PHP 8.x, no extension install needed. Good.

### 3. Signature base construction

The thing that's actually subtle. RFC 9421 says you concatenate covered components in the order listed in `Signature-Input`, lowercase header names, structured field handling for `Signature-Key`, etc. The aauth Python lib's `build_signature_base()` is the reference; we mirror it.

Specifically for `Signature-Key`: the *structured field* representation has to match exactly. If we serialize differently than the signer (say, different whitespace handling), we get a different base, signature fails. This is where small bugs lurk.

### 4. JWK → public key

```php
function jwkToOpenSslKey(array $jwk) {
    $kty = $jwk['kty'] ?? null;
    $crv = $jwk['crv'] ?? null;

    if ($kty === 'OKP' && $crv === 'Ed25519') {
        return ['type' => 'ed25519', 'public' => b64url_decode($jwk['x'])];
        // verification done via sodium_crypto_sign_verify_detached, not openssl
    }

    if ($kty === 'EC' && $crv === 'P-256') {
        // Build a DER SubjectPublicKeyInfo for P-256 from x, y.
        $x = b64url_decode($jwk['x']);
        $y = b64url_decode($jwk['y']);
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \Exception('P-256 x/y must be 32 bytes each');
        }
        $point = "\x04" . $x . $y;  // uncompressed point
        $spki = build_p256_spki($point);  // hard-coded ASN.1 prefix + point
        $pem = "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split(base64_encode($spki), 64, "\n") .
               "-----END PUBLIC KEY-----\n";
        return ['type' => 'ecdsa-p256', 'public' => openssl_pkey_get_public($pem)];
    }

    throw new \Exception("unsupported JWK: kty={$kty} crv={$crv}");
}
```

The `build_p256_spki` step is just prepending a fixed 26-byte ASN.1 prefix (the OID for `id-ecPublicKey` + named curve `prime256v1`) to the uncompressed point. Hard-coded constant; no asn1 library needed.

### 5. JWT verification

PHP has `firebase/php-jwt` but it requires Composer and pulls in dependencies. For our drop-in goal, hand-roll a 60-line JWT verifier:

- Split on `.`, base64url-decode header and payload
- Look up public key for `kid` (already have JWK→key conversion above)
- Verify signature over `header.payload` bytes
- Validate `iat`/`exp`/`nbf`
- Return decoded payload claims

### 6. JWKS caching

Shared hosting means every PHP request is a cold start. Without caching, every incoming AAuth request triggers two HTTPS fetches to the agent's domain. Slow and rude.

Cache by writing JSON to `cache_dir/jwks-{sha256(jwks_uri)}.json` with TTL (default 1h). Simple file-based cache. Honor `Cache-Control: max-age=` from the JWKS response if present.

## Testing strategy

1. **Unit tests** for each piece (signature base, ECDSA wire conversion, JWK conversion).
2. **Fixtures from real signers.** I'll export ~10 signed requests from our TS test client and ~10 from Christian's Python `aauth==0.3.3` (after his fix lands, or with Ed25519 keys until then). These become golden tests — if our verifier accepts both, we have real interop.
3. **`wisdom.clawdrey.com` as the integration test.** A live AAuth resource we can hit from any AAuth client.

## Distribution

- **GitHub:** `clawdreyhepburn/aauth-php`
- **Packagist:** publish for the Composer-using crowd (`composer require clawdreyhepburn/aauth-php`)
- **Single-file release:** ship a concatenated `aauth-bundle.php` in releases for the no-Composer crowd. Generate via simple build script that cats the source files.
- **License:** MIT (matches Posta's lib).
- **README:** "AAuth verification for PHP. Drop one file in. Verify signed AI-agent requests on shared hosting." Include a 5-minute WordPress quickstart.

## Timeline

| Day | Output |
|-----|--------|
| **Sat 2026-05-02** | Repo scaffold, signature-base + ECDSA wire conversion + JWK→key, with unit tests. ~400 LOC. |
| **Sun 2026-05-03** | RequestVerifier glue, JWT parsing, fixture-based interop tests against TS-signed and Ed25519-signed requests. ~600 LOC total. |
| **Mon 2026-05-04** | Wisdom corpus written, `wisdom.clawdrey.com` PHP wrapper around RequestVerifier, deploy to DreamHost. |
| **Tue 2026-05-05** | README, packagist publish, blog post. |

3-4 day project, doable around other work.

## Open questions for Sarah

1. **DreamHost PHP version** — what's clawdrey.com running? Confirm 8.x. (Sodium ext for Ed25519 needs ≥7.2; openssl is universal.)
2. **DreamHost subdomain ergonomics** — easiest is probably `wisdom.clawdrey.com` as a separate domain entry pointing at a `~/wisdom.clawdrey.com/` directory? Or we can do `clawdrey.com/wisdom/` if subdomains are annoying. Subdomain is cleaner for the demo story.
3. **Naming** — `aauth-php` or `clawdrey-aauth-php` or something more evocative? "Pearl" comes to mind — pearl as in proof-of-possession lobster pun, plus PEARL = "PHP Embedded AAuth Resource Library" works as a backronym. Not committing to it but it's there.
4. **License** — MIT, matching Christian and Dick? Or Apache 2.0 for the patent grant? Apache 2.0 is more standards-friendly. Lean Apache 2.0.

## Why this matters strategically

- **AAuth has 0 PHP implementations.** First-mover lets us shape the PHP idiom for the spec.
- **WordPress alone is ~40% of the web.** A credible PHP AAuth lib is the bridge from "spec demos" to "real sites can verify AI agent identity."
- **Sarah's audience.** Identity people read this as taking the spec seriously enough to do the unglamorous platform work, not just the pretty Node demos.
- **Interop story.** Once we have TS, Python, *and* PHP all interoperating, that's a real cross-language spec, not a single-language toy.
- **`wisdom.clawdrey.com` is shareable.** Lobster-Audrey delivering style wisdom over AAuth-verified channels is something IIW people will screenshot.

## What we ship at the end

- `github.com/clawdreyhepburn/aauth-php` — open source, MIT or Apache, with README + example
- `packagist.org/packages/clawdreyhepburn/aauth-php` — installable
- `wisdom.clawdrey.com` — public AAuth resource, lobster-Audrey persona
- A blog post at clawdrey.com explaining what we built and why
- Cross-implementation interop fixtures shared with Posta and (eventually) Hardt

Done. Bed.
