<?php

/**
 * aauth-php — bundled single-file release
 * https://github.com/clawdreyhepburn/aauth-php
 *
 * Generated 2026-05-01T10:26:55Z
 *
 * Drop this file into any PHP project; require_once it; use the
 * Clawdrey\AAuth\RequestVerifier class.
 *
 * Apache 2.0 © 2026 Clawdrey Hepburn (clawdrey.hepburn@engageidentity.com)
 */

declare(strict_types=1);

// ------------------------------------------------------------------
// src/AAuthException.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;

/**
 * Base class for all aauth-php exceptions. Catch this if you don't care
 * about the specific failure mode; otherwise catch the subclasses.
 */
class AAuthException extends \RuntimeException {}

/** Headers missing or malformed. */
class MalformedRequestException extends AAuthException {}

/** Cryptographic verification failed. */
class InvalidSignatureException extends AAuthException {}

/** Token expired, not-yet-valid, or fails freshness window. */
class TokenLifetimeException extends AAuthException {}

/** Could not retrieve a public key for the given identifier. */
class KeyResolutionException extends AAuthException {}

/** Caller's `created` timestamp outside acceptable window. */
class StaleSignatureException extends AAuthException {}

/** Request authority does not match this verifier's accepted authorities. */
class WrongAudienceException extends AAuthException {}

/** Unsupported scheme/algorithm/JWK type. */
class UnsupportedException extends AAuthException {}

// ------------------------------------------------------------------
// src/EcdsaWire.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;

/**
 * Convert ECDSA P-256 signatures between RFC 9421 wire format (raw r||s, 64 bytes)
 * and ASN.1 DER (what OpenSSL's verify() expects).
 *
 * Why this matters: RFC 9421 §3.3.1 specifies ecdsa-p256-sha256 signatures as
 * the raw concatenation of r and s, each padded to 32 bytes. PHP's
 * openssl_verify() only accepts DER-encoded ECDSA-Sig-Value. So every PHP
 * implementation of RFC 9421 needs this conversion.
 *
 * (Christian Posta's aauth_signing==0.1.2 uses the standard
 * `http_message_signatures` Python library which handles this internally;
 * we don't get that for free in PHP.)
 */
final class EcdsaWire
{
    private const COMPONENT_LEN_P256 = 32;

    /**
     * Convert raw r||s (64 bytes for P-256) to ASN.1 DER ECDSA-Sig-Value.
     *
     * The DER encoding is a SEQUENCE of two INTEGERs:
     *
     *   ECDSA-Sig-Value ::= SEQUENCE {
     *     r INTEGER,
     *     s INTEGER
     *   }
     *
     * Note ASN.1 INTEGERs are signed two's-complement, so if the high bit of
     * the first byte is set we MUST prepend 0x00 to keep the value positive.
     *
     * @throws \InvalidArgumentException if input is not 64 bytes
     */
    public static function rawToDer(string $raw): string
    {
        $expected = self::COMPONENT_LEN_P256 * 2;
        if (strlen($raw) !== $expected) {
            throw new \InvalidArgumentException(sprintf(
                'expected %d bytes for P-256 raw signature, got %d',
                $expected,
                strlen($raw)
            ));
        }

        $r = substr($raw, 0, self::COMPONENT_LEN_P256);
        $s = substr($raw, self::COMPONENT_LEN_P256, self::COMPONENT_LEN_P256);

        $rEncoded = self::encodeAsn1Integer($r);
        $sEncoded = self::encodeAsn1Integer($s);

        $body = $rEncoded . $sEncoded;
        return "\x30" . self::encodeAsn1Length(strlen($body)) . $body;
    }

    /**
     * Convert ASN.1 DER ECDSA-Sig-Value back to raw r||s (64 bytes for P-256).
     *
     * Accepts the full SEQUENCE encoding and returns the canonical r||s with
     * each component left-padded to 32 bytes.
     *
     * @throws \InvalidArgumentException if input is not a well-formed
     *         ECDSA-Sig-Value, or if r or s is too long for P-256.
     */
    public static function derToRaw(string $der): string
    {
        $offset = 0;
        $len = strlen($der);

        if ($len < 2 || $der[$offset] !== "\x30") {
            throw new \InvalidArgumentException('expected ASN.1 SEQUENCE tag (0x30)');
        }
        $offset++;

        [$seqLen, $seqLenBytes] = self::decodeAsn1Length($der, $offset);
        $offset += $seqLenBytes;
        if ($offset + $seqLen !== $len) {
            throw new \InvalidArgumentException('ASN.1 SEQUENCE length mismatch');
        }

        // r INTEGER
        if ($der[$offset] !== "\x02") {
            throw new \InvalidArgumentException('expected ASN.1 INTEGER tag for r');
        }
        $offset++;
        [$rLen, $rLenBytes] = self::decodeAsn1Length($der, $offset);
        $offset += $rLenBytes;
        $r = substr($der, $offset, $rLen);
        $offset += $rLen;

        // s INTEGER
        if ($der[$offset] !== "\x02") {
            throw new \InvalidArgumentException('expected ASN.1 INTEGER tag for s');
        }
        $offset++;
        [$sLen, $sLenBytes] = self::decodeAsn1Length($der, $offset);
        $offset += $sLenBytes;
        $s = substr($der, $offset, $sLen);

        return self::normalizeAsn1Integer($r) . self::normalizeAsn1Integer($s);
    }

    /**
     * Encode a fixed-width unsigned big-endian integer (the r or s value)
     * as an ASN.1 INTEGER. Strips leading zeros, then prepends 0x00 if
     * needed to disambiguate from a negative number.
     */
    private static function encodeAsn1Integer(string $component): string
    {
        // Strip leading zero bytes.
        $component = ltrim($component, "\x00");
        // ASN.1 INTEGER 0 is a single 0x00 byte, not the empty string.
        if ($component === '') {
            $component = "\x00";
        }
        // Prepend 0x00 if high bit is set (so it's interpreted as positive).
        if ((ord($component[0]) & 0x80) !== 0) {
            $component = "\x00" . $component;
        }
        return "\x02" . self::encodeAsn1Length(strlen($component)) . $component;
    }

    /**
     * Strip the optional leading 0x00 from an ASN.1 INTEGER and left-pad the
     * remaining magnitude to COMPONENT_LEN_P256 bytes.
     *
     * @throws \InvalidArgumentException if the magnitude is longer than
     *         COMPONENT_LEN_P256 bytes.
     */
    private static function normalizeAsn1Integer(string $integer): string
    {
        // Drop the leading 0x00 if present (it was added to disambiguate sign).
        if (strlen($integer) > 0 && $integer[0] === "\x00") {
            $integer = substr($integer, 1);
        }
        if (strlen($integer) > self::COMPONENT_LEN_P256) {
            throw new \InvalidArgumentException(sprintf(
                'ASN.1 INTEGER too long for P-256: %d bytes',
                strlen($integer)
            ));
        }
        return str_pad($integer, self::COMPONENT_LEN_P256, "\x00", STR_PAD_LEFT);
    }

    /**
     * Encode a non-negative length in ASN.1 BER short or long form.
     */
    private static function encodeAsn1Length(int $len): string
    {
        if ($len < 0) {
            throw new \InvalidArgumentException('length must be non-negative');
        }
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Decode an ASN.1 BER length starting at $offset.
     *
     * @return array{0: int, 1: int} [length, bytes consumed]
     */
    private static function decodeAsn1Length(string $der, int $offset): array
    {
        $first = ord($der[$offset]);
        if ($first < 0x80) {
            return [$first, 1];
        }
        $numBytes = $first & 0x7F;
        if ($numBytes === 0 || $numBytes > 4) {
            // BER allows indefinite length (0) but DER does not; we don't
            // need lengths > 2^32 either. Reject.
            throw new \InvalidArgumentException('unsupported ASN.1 length form');
        }
        $len = 0;
        for ($i = 1; $i <= $numBytes; $i++) {
            $len = ($len << 8) | ord($der[$offset + $i]);
        }
        return [$len, $numBytes + 1];
    }
}

// ------------------------------------------------------------------
// src/JwkConverter.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;

/**
 * Convert JWK (JSON Web Key, RFC 7517) representations into the form needed
 * for signature verification on this PHP runtime.
 *
 * Supports:
 *   - kty=OKP, crv=Ed25519     → raw 32-byte public key (use sodium ext)
 *   - kty=EC,  crv=P-256       → OpenSSL public key resource (use openssl ext)
 *
 * Christian Posta's aauth_signing==0.1.2 only handles Ed25519 here, which is
 * a real interop gap (filed as christian-posta/aauth-full-demo#1). We support
 * both from day one.
 */
final class JwkConverter
{
    /**
     * P-256 SubjectPublicKeyInfo prefix.
     *
     * The DER encoding of the SPKI for any P-256 public key always has this
     * exact 26-byte prefix, followed by 0x04 || x || y (the uncompressed point).
     * The structure encodes:
     *   SEQUENCE {
     *     SEQUENCE {
     *       OID 1.2.840.10045.2.1   (id-ecPublicKey)
     *       OID 1.2.840.10045.3.1.7 (prime256v1 / secp256r1)
     *     }
     *     BIT STRING (66 bytes: 0x00 padding + 0x04 + x[32] + y[32])
     *   }
     *
     * Hard-coding it avoids pulling in an ASN.1 library — the bytes are
     * canonical and don't change.
     */
    private const P256_SPKI_PREFIX = "\x30\x59" .                  // SEQUENCE 89
        "\x30\x13" .                                                // SEQUENCE 19
        "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" .                   // OID id-ecPublicKey
        "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" .               // OID prime256v1
        "\x03\x42\x00";                                             // BIT STRING 66, 0 unused bits

    /**
     * @param array<string, mixed> $jwk
     * @return array{type: 'ed25519', public: string} | array{type: 'ecdsa-p256', public: \OpenSSLAsymmetricKey}
     *
     * @throws \InvalidArgumentException for unsupported or malformed JWKs.
     */
    public static function jwkToPublicKey(array $jwk): array
    {
        $kty = $jwk['kty'] ?? null;
        $crv = $jwk['crv'] ?? null;

        if ($kty === 'OKP' && $crv === 'Ed25519') {
            return self::convertEd25519($jwk);
        }

        if ($kty === 'EC' && $crv === 'P-256') {
            return self::convertP256($jwk);
        }

        throw new \InvalidArgumentException(sprintf(
            'unsupported JWK: kty=%s crv=%s',
            self::stringify($kty),
            self::stringify($crv)
        ));
    }

    /**
     * Compute the JWK Thumbprint per RFC 7638. Used for proof-of-possession
     * via the cnf.jkt claim.
     */
    public static function jwkThumbprint(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;

        if ($kty === 'OKP') {
            $canonical = [
                'crv' => $jwk['crv'] ?? null,
                'kty' => 'OKP',
                'x'   => $jwk['x'] ?? null,
            ];
        } elseif ($kty === 'EC') {
            $canonical = [
                'crv' => $jwk['crv'] ?? null,
                'kty' => 'EC',
                'x'   => $jwk['x'] ?? null,
                'y'   => $jwk['y'] ?? null,
            ];
        } else {
            throw new \InvalidArgumentException("cannot compute thumbprint for kty=$kty");
        }

        // RFC 7638: canonical JSON, lex-sorted required fields, no whitespace.
        $json = json_encode(
            $canonical,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
        return self::base64UrlEncode(hash('sha256', $json, true));
    }

    /**
     * @param array<string, mixed> $jwk
     * @return array{type: 'ed25519', public: string}
     */
    private static function convertEd25519(array $jwk): array
    {
        if (!isset($jwk['x']) || !is_string($jwk['x'])) {
            throw new \InvalidArgumentException('Ed25519 JWK missing x parameter');
        }
        $public = self::base64UrlDecode($jwk['x']);
        if (strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \InvalidArgumentException(sprintf(
                'Ed25519 public key must be %d bytes, got %d',
                SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES,
                strlen($public)
            ));
        }
        return ['type' => 'ed25519', 'public' => $public];
    }

    /**
     * @param array<string, mixed> $jwk
     * @return array{type: 'ecdsa-p256', public: \OpenSSLAsymmetricKey}
     */
    private static function convertP256(array $jwk): array
    {
        if (!isset($jwk['x'], $jwk['y']) || !is_string($jwk['x']) || !is_string($jwk['y'])) {
            throw new \InvalidArgumentException('P-256 JWK missing x and/or y parameter');
        }

        $x = self::base64UrlDecode($jwk['x']);
        $y = self::base64UrlDecode($jwk['y']);

        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \InvalidArgumentException(sprintf(
                'P-256 x and y must each be 32 bytes (got %d, %d)',
                strlen($x),
                strlen($y)
            ));
        }

        // Uncompressed point: 0x04 || x || y
        $point = "\x04" . $x . $y;
        $spki = self::P256_SPKI_PREFIX . $point;

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new \InvalidArgumentException(
                'OpenSSL rejected reconstructed P-256 SPKI: ' . openssl_error_string()
            );
        }

        return ['type' => 'ecdsa-p256', 'public' => $key];
    }

    public static function base64UrlDecode(string $s): string
    {
        $s = strtr($s, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad > 0) {
            $s .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($s, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('invalid base64url input');
        }
        return $decoded;
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function stringify($v): string
    {
        if ($v === null) return '(missing)';
        if (is_string($v)) return $v;
        return gettype($v);
    }
}

// ------------------------------------------------------------------
// src/HttpSignatures.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;

/**
 * Parsers for the AAuth HTTP signature headers.
 *
 *   - Signature-Input: per RFC 9421, structured-field "Inner List" with params
 *   - Signature: per RFC 9421, structured-field "Byte Sequence"
 *   - Signature-Key: AAuth-specific, structured-field "Item" with params
 *
 * For our purposes we don't need a full SF parser — these headers all follow
 * a tightly constrained shape. We use targeted regex + light hand-parsing
 * so we don't pull in another library.
 */
final class HttpSignatures
{
    /**
     * Parse a Signature-Input header value.
     *
     * Example:
     *   sig=("@method" "@authority" "@path" "signature-key");created=1777630299
     *
     * @return array{label: string, components: list<string>, params: array<string, string|int>}
     */
    public static function parseSignatureInput(string $header): array
    {
        // label = "(" components ")" ";" params
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=\((.*?)\)(.*)$/', $header, $m)) {
            throw new \InvalidArgumentException("malformed Signature-Input: $header");
        }

        $label = $m[1];
        $componentsList = trim($m[2]);
        $paramsTail = $m[3];

        $components = [];
        if ($componentsList !== '') {
            // Components are quoted strings separated by whitespace.
            preg_match_all('/"([^"]*)"/', $componentsList, $cm);
            $components = $cm[1];
        }

        $params = self::parseParams($paramsTail);

        return [
            'label' => $label,
            'components' => $components,
            'params' => $params,
        ];
    }

    /**
     * Parse a Signature header value.
     *
     * Example:
     *   sig=:I6Bjqd...nA==:
     *
     * @return array{label: string, signature: string} where signature is raw bytes
     */
    public static function parseSignature(string $header): array
    {
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=:([^:]*):$/', $header, $m)) {
            throw new \InvalidArgumentException("malformed Signature header: $header");
        }
        $label = $m[1];
        $b64 = $m[2];
        $raw = base64_decode($b64, true);
        if ($raw === false) {
            throw new \InvalidArgumentException('Signature header has invalid base64');
        }
        return ['label' => $label, 'signature' => $raw];
    }

    /**
     * Parse a Signature-Key header value.
     *
     * Example schemes (per AAuth SIG-KEY spec):
     *   sig=jwt;jwt="eyJhbGc..."
     *   sig=jwks_uri;id="https://example.com";dwk="aauth-agent.json";kid="x"
     *   sig=hwk;jwk="{...}"
     *   sig=jkt-jwt;jwt="..."
     *
     * @return array{label: string, scheme: string, params: array<string, string>}
     */
    public static function parseSignatureKey(string $header): array
    {
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=([A-Za-z][A-Za-z0-9_-]*)(.*)$/', $header, $m)) {
            throw new \InvalidArgumentException("malformed Signature-Key: $header");
        }
        $label = $m[1];
        $scheme = $m[2];
        $paramsTail = $m[3];

        return [
            'label' => $label,
            'scheme' => $scheme,
            'params' => self::parseParams($paramsTail, asString: true),
        ];
    }

    /**
     * Parse a parameter tail like ;a=1;b="x";c=token. Values are either
     * tokens (returned as-is, integer if numeric and $asString is false)
     * or quoted strings (returned without the quotes).
     *
     * @return array<string, string|int>
     */
    private static function parseParams(string $tail, bool $asString = false): array
    {
        $params = [];
        // Split on `;` not preceded by `\` (we don't actually do escape handling
        // per RFC 8941, but our headers don't use embedded semicolons so it's fine).
        $pieces = array_filter(array_map('trim', explode(';', $tail)));
        foreach ($pieces as $piece) {
            if ($piece === '') continue;
            if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)\s*(?:=\s*(.*))?$/', $piece, $pm)) {
                throw new \InvalidArgumentException("malformed param: $piece");
            }
            $name = $pm[1];
            $rawVal = $pm[2] ?? '';
            $value = self::parseParamValue($rawVal, $asString);
            $params[$name] = $value;
        }
        return $params;
    }

    /**
     * @return string|int
     */
    private static function parseParamValue(string $raw, bool $asString)
    {
        $raw = trim($raw);
        if ($raw === '') {
            return $asString ? '' : 1;  // bare boolean true → 1
        }
        // Quoted string?
        if (strlen($raw) >= 2 && $raw[0] === '"' && $raw[strlen($raw) - 1] === '"') {
            $inner = substr($raw, 1, -1);
            // Per RFC 8941 quoted strings can contain \" and \\ escapes.
            return str_replace(['\\\\', '\\"'], ['\\', '"'], $inner);
        }
        // Numeric?
        if (!$asString && preg_match('/^-?\d+$/', $raw)) {
            return (int)$raw;
        }
        // Token / unquoted bareword
        return $raw;
    }

    /**
     * Re-serialize a Signature-Input value's "params section" — i.e. the part
     * after the components list — exactly as the signer would have written it.
     *
     * Used to extract the @signature-params trailer for the signature base.
     *
     * In practice we don't re-serialize: we slice the original header. This
     * helper is here for tests and explicit re-construction.
     */
    public static function extractSignatureParams(string $signatureInputHeader): string
    {
        // Strip "<label>=" prefix; return the rest verbatim.
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=(.*)$/s', $signatureInputHeader, $m)) {
            throw new \InvalidArgumentException("malformed Signature-Input: $signatureInputHeader");
        }
        return $m[2];
    }
}

// ------------------------------------------------------------------
// src/SignatureBase.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;

/**
 * Build the RFC 9421 signature base string that the signer hashes-and-signs.
 *
 * The base is a newline-separated list of "<component-id>: <value>" lines,
 * where component-id is either a derived component (@method, @authority,
 * @path, @query, @signature-params) or a lowercase HTTP header name. The
 * final line is always "@signature-params".
 *
 * This matches the construction in `aauth_signing.signing.build_signature_base`
 * (Posta's Python lib) and `@aauth/mcp-resource`'s buildSignatureBase
 * (Hardt's TS lib) — both of which ultimately defer to RFC 9421 §2.5.
 */
final class SignatureBase
{
    /**
     * @param array<string, string> $headers       lowercase keys
     * @param list<string>          $coveredComponents components in the order specified by Signature-Input
     * @param string                $signatureParams the part of Signature-Input after "<label>="
     */
    public static function build(
        string $method,
        string $authority,
        string $path,
        ?string $query,
        array $headers,
        ?string $body,
        string $signatureKeyHeader,
        array $coveredComponents,
        string $signatureParams
    ): string {
        $lowerHeaders = [];
        foreach ($headers as $k => $v) {
            $lowerHeaders[strtolower($k)] = $v;
        }
        // signature-key isn't always present in $headers (callers may pass
        // it separately); ensure it's available for component resolution.
        $lowerHeaders['signature-key'] = $signatureKeyHeader;

        $lines = [];
        foreach ($coveredComponents as $component) {
            $lines[] = sprintf(
                '"%s": %s',
                $component,
                self::resolveComponent(
                    $component,
                    $method,
                    $authority,
                    $path,
                    $query,
                    $lowerHeaders,
                    $body
                )
            );
        }
        $lines[] = '"@signature-params": ' . $signatureParams;

        return implode("\n", $lines);
    }

    /**
     * @param array<string, string> $lowerHeaders
     */
    private static function resolveComponent(
        string $component,
        string $method,
        string $authority,
        string $path,
        ?string $query,
        array $lowerHeaders,
        ?string $body
    ): string {
        switch ($component) {
            case '@method':
                return strtoupper($method);
            case '@authority':
                return strtolower($authority);
            case '@path':
                return $path;
            case '@query':
                if ($query === null || $query === '') {
                    throw new \InvalidArgumentException('@query covered but query string is empty');
                }
                return '?' . $query;
            case '@target-uri':
                $u = $path;
                if ($query !== null && $query !== '') {
                    $u .= '?' . $query;
                }
                return $u;
            default:
                if (str_starts_with($component, '@')) {
                    throw new \InvalidArgumentException("unsupported derived component: $component");
                }
                $key = strtolower($component);
                if (!isset($lowerHeaders[$key])) {
                    throw new \InvalidArgumentException("missing header for covered component: $component");
                }
                // RFC 9421 §2.1 says: trim leading/trailing whitespace; collapse internal
                // obs-fold whitespace. Simple `trim` covers our cases.
                return trim($lowerHeaders[$key]);
        }
    }
}

// ------------------------------------------------------------------
// src/JwtVerifier.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;
/**
 * Minimal JWT verifier supporting the algorithms AAuth uses on the wire:
 *
 *   - ES256 (ECDSA P-256, SHA-256)  → kty=EC,  crv=P-256
 *   - EdDSA (Ed25519)               → kty=OKP, crv=Ed25519
 *
 * No external dependencies. We hand-roll because every PHP JWT library on
 * Packagist (firebase/php-jwt, lcobucci/jwt, etc.) pulls in extra packages
 * that defeat the "drop one file into shared hosting" goal.
 *
 * Supports JWS Compact Serialization only. JWE/JWS-JSON not in scope.
 */
final class JwtVerifier
{
    /**
     * Verify a compact JWS and return its decoded payload claims.
     *
     * @param string                                       $jwt          compact JWS
     * @param callable(string $kid, ?string $iss): array  $resolveJwk   given a kid (and optionally iss),
     *                                                                  return the JWK to verify against
     * @param array{
     *   leeway?: int,
     *   require_iat?: bool,
     *   require_exp?: bool,
     *   expected_typ?: string|null,
     *   audience?: string|null,
     *   issuer?: string|null,
     * } $opts
     *
     * @return array{header: array<string, mixed>, payload: array<string, mixed>}
     *
     * @throws JwtException
     */
    public static function verify(string $jwt, callable $resolveJwk, array $opts = []): array
    {
        $leeway = $opts['leeway'] ?? 60;
        $expectedTyp = $opts['expected_typ'] ?? null;

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new JwtException('JWT must have 3 parts');
        }
        [$h64, $p64, $s64] = $parts;

        try {
            $header = json_decode(JwkConverter::base64UrlDecode($h64), true, 16, JSON_THROW_ON_ERROR);
            $payload = json_decode(JwkConverter::base64UrlDecode($p64), true, 32, JSON_THROW_ON_ERROR);
            $sig = JwkConverter::base64UrlDecode($s64);
        } catch (\Throwable $e) {
            throw new JwtException('JWT decode failed: ' . $e->getMessage(), 0, $e);
        }

        if (!is_array($header) || !is_array($payload)) {
            throw new JwtException('JWT header/payload not JSON objects');
        }

        $alg = $header['alg'] ?? null;
        if (!is_string($alg)) {
            throw new JwtException('JWT header missing alg');
        }
        if (!in_array($alg, ['ES256', 'EdDSA'], true)) {
            throw new JwtException("unsupported JWT alg: $alg");
        }

        if ($expectedTyp !== null) {
            if (($header['typ'] ?? null) !== $expectedTyp) {
                throw new JwtException(sprintf(
                    'JWT typ mismatch: expected %s, got %s',
                    $expectedTyp,
                    self::stringify($header['typ'] ?? null)
                ));
            }
        }

        $kid = $header['kid'] ?? null;
        if (!is_string($kid)) {
            throw new JwtException('JWT header missing kid');
        }

        $iss = is_string($payload['iss'] ?? null) ? $payload['iss'] : null;
        $jwk = $resolveJwk($kid, $iss);
        if (!is_array($jwk)) {
            throw new JwtException("kid resolver did not return a JWK for kid=$kid");
        }

        $signingInput = $h64 . '.' . $p64;
        self::verifySignature($alg, $signingInput, $sig, $jwk);

        // Time validation — IETF JWT spec §4.1.4/4.1.5
        $now = time();
        if (isset($payload['exp'])) {
            if (!is_int($payload['exp']) || $payload['exp'] + $leeway < $now) {
                throw new JwtException('JWT expired');
            }
        } elseif (!empty($opts['require_exp'])) {
            throw new JwtException('JWT missing required exp');
        }

        if (isset($payload['nbf'])) {
            if (!is_int($payload['nbf']) || $payload['nbf'] - $leeway > $now) {
                throw new JwtException('JWT nbf not yet reached');
            }
        }

        if (isset($payload['iat'])) {
            if (!is_int($payload['iat']) || $payload['iat'] - $leeway > $now) {
                throw new JwtException('JWT iat is in the future');
            }
        } elseif (!empty($opts['require_iat'])) {
            throw new JwtException('JWT missing required iat');
        }

        if (isset($opts['issuer']) && $opts['issuer'] !== null) {
            if (($payload['iss'] ?? null) !== $opts['issuer']) {
                throw new JwtException(sprintf(
                    'JWT iss mismatch: expected %s, got %s',
                    $opts['issuer'],
                    self::stringify($payload['iss'] ?? null)
                ));
            }
        }

        if (isset($opts['audience']) && $opts['audience'] !== null) {
            $aud = $payload['aud'] ?? null;
            $audList = is_array($aud) ? $aud : [$aud];
            if (!in_array($opts['audience'], $audList, true)) {
                throw new JwtException(sprintf(
                    'JWT aud does not include expected audience %s',
                    $opts['audience']
                ));
            }
        }

        return ['header' => $header, 'payload' => $payload];
    }

    /**
     * Verify the signature bytes over the signing input using the given JWK.
     *
     * @param array<string, mixed> $jwk
     */
    private static function verifySignature(string $alg, string $signingInput, string $sig, array $jwk): void
    {
        $key = JwkConverter::jwkToPublicKey($jwk);

        if ($alg === 'ES256') {
            if ($key['type'] !== 'ecdsa-p256') {
                throw new JwtException('alg=ES256 requires P-256 JWK');
            }
            if (strlen($sig) !== 64) {
                throw new JwtException('ES256 signature must be 64 bytes');
            }
            $der = EcdsaWire::rawToDer($sig);
            $ok = openssl_verify($signingInput, $der, $key['public'], OPENSSL_ALGO_SHA256);
            if ($ok !== 1) {
                throw new JwtException('ES256 signature verification failed');
            }
            return;
        }

        if ($alg === 'EdDSA') {
            if ($key['type'] !== 'ed25519') {
                throw new JwtException('alg=EdDSA requires Ed25519 JWK');
            }
            $ok = sodium_crypto_sign_verify_detached($sig, $signingInput, $key['public']);
            if (!$ok) {
                throw new JwtException('Ed25519 signature verification failed');
            }
            return;
        }

        throw new JwtException("unsupported alg: $alg");
    }

    private static function stringify($v): string
    {
        if ($v === null) return 'null';
        if (is_string($v)) return $v;
        return gettype($v);
    }
}

class JwtException extends \RuntimeException {}

// ------------------------------------------------------------------
// src/JwksFetcher.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;
/**
 * Default JWKS fetcher with file-based caching, suitable for shared hosting.
 *
 * AAuth's two-step discovery (per SIG-KEY §3.5):
 *   1. GET {id}/.well-known/{dwk}    → metadata document
 *   2. extract jwks_uri from metadata
 *   3. GET jwks_uri                  → JWKS
 *
 * This is the bottleneck on a cold-start PHP deployment: each request
 * triggers two HTTPS hops to the agent's domain. We cache aggressively
 * (default 1 hour) to amortize.
 *
 * Cache files live in a directory you control. We name them by SHA-256 of
 * the URL so there's no path-traversal risk.
 */
final class JwksFetcher
{
    /** @var string */
    private string $cacheDir;
    /** @var int */
    private int $defaultTtl;
    /** @var int */
    private int $timeoutMs;
    /** @var bool */
    private bool $verifyTls;

    /**
     * @param array{cache_dir?: string|null, ttl_seconds?: int, timeout_ms?: int, verify_tls?: bool} $opts
     */
    public function __construct(array $opts = [])
    {
        $this->cacheDir = $opts['cache_dir'] ?? sys_get_temp_dir() . '/aauth-jwks-cache';
        $this->defaultTtl = $opts['ttl_seconds'] ?? 3600;
        $this->timeoutMs = $opts['timeout_ms'] ?? 5000;
        $this->verifyTls = $opts['verify_tls'] ?? true;

        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0700, true);
        }
    }

    /**
     * Two-step discovery. Used as the callback for the `jwks_uri` Signature-Key scheme.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function fetchTwoStep(string $id, string $dwk, ?string $kid = null): array
    {
        $wellKnown = rtrim($id, '/') . '/.well-known/' . $dwk;
        $meta = $this->fetchJson($wellKnown);

        $jwksUri = $meta['jwks_uri'] ?? null;
        if (!is_string($jwksUri)) {
            throw new MalformedRequestException("metadata at $wellKnown lacks jwks_uri");
        }

        $jwks = $this->fetchJson($jwksUri);
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new MalformedRequestException("JWKS at $jwksUri lacks keys array");
        }

        return $jwks;
    }

    /**
     * Single-step JWKS fetch. Used directly when caller already has a jwks_uri.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function fetchJwks(string $jwksUri): array
    {
        $jwks = $this->fetchJson($jwksUri);
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new MalformedRequestException("JWKS at $jwksUri lacks keys array");
        }
        return $jwks;
    }

    /**
     * Find a key by kid. Returns null if not present.
     *
     * @param array{keys: list<array<string, mixed>>} $jwks
     * @return array<string, mixed>|null
     */
    public static function findKid(array $jwks, string $kid): ?array
    {
        foreach ($jwks['keys'] as $k) {
            if (($k['kid'] ?? null) === $kid) {
                return $k;
            }
        }
        return null;
    }

    /**
     * Fetch JSON with file-based cache. Cache TTL honors response
     * Cache-Control: max-age= when present.
     *
     * @return array<string, mixed>
     */
    public function fetchJson(string $url): array
    {
        $cacheFile = $this->cacheDir . '/' . hash('sha256', $url) . '.json';

        if (is_readable($cacheFile)) {
            $cached = json_decode((string)file_get_contents($cacheFile), true);
            if (is_array($cached) && isset($cached['expires_at'], $cached['body'])
                && time() < $cached['expires_at']
                && is_array($cached['body'])
            ) {
                return $cached['body'];
            }
        }

        [$body, $maxAge] = $this->httpGetJson($url);

        $ttl = $maxAge !== null ? min($maxAge, $this->defaultTtl * 4) : $this->defaultTtl;
        @file_put_contents($cacheFile, json_encode([
            'fetched_at' => time(),
            'expires_at' => time() + $ttl,
            'url'        => $url,
            'body'       => $body,
        ]), LOCK_EX);

        return $body;
    }

    /**
     * @return array{0: array<string, mixed>, 1: int|null}
     */
    private function httpGetJson(string $url): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new KeyResolutionException("curl_init failed for $url");
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT_MS     => $this->timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $this->timeoutMs,
            CURLOPT_SSL_VERIFYPEER => $this->verifyTls,
            CURLOPT_SSL_VERIFYHOST => $this->verifyTls ? 2 : 0,
            CURLOPT_HEADER         => true,
            CURLOPT_USERAGENT      => 'aauth-php/0.1 (+https://github.com/clawdreyhepburn/aauth-php)',
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);

        $response = curl_exec($ch);
        if ($response === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new KeyResolutionException("HTTP fetch failed for $url: $err");
        }

        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        // curl_close is a no-op since PHP 8.0 and deprecated in 8.5; rely on GC.

        if ($status < 200 || $status >= 300) {
            throw new KeyResolutionException("HTTP $status for $url");
        }

        $headerStr = (string)substr((string)$response, 0, $headerSize);
        $body = (string)substr((string)$response, $headerSize);

        $maxAge = self::parseMaxAge($headerStr);

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new MalformedRequestException("non-JSON or non-object response from $url");
        }
        return [$decoded, $maxAge];
    }

    private static function parseMaxAge(string $headerStr): ?int
    {
        if (preg_match('/^cache-control:\s*[^\r\n]*max-age\s*=\s*(\d+)/im', $headerStr, $m)) {
            return (int)$m[1];
        }
        return null;
    }
}

// ------------------------------------------------------------------
// src/RequestVerifier.php
// ------------------------------------------------------------------

namespace Clawdrey\AAuth;
/**
 * Top-level AAuth request verifier. The public face of aauth-php.
 *
 * Usage:
 *
 *   $verifier = new RequestVerifier([
 *       'canonical_authorities' => ['wisdom.clawdrey.com'],
 *   ]);
 *
 *   try {
 *       $result = $verifier->verifyRequest([
 *           'method'           => $_SERVER['REQUEST_METHOD'],
 *           'uri'              => 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
 *           'headers'          => getallheaders(),
 *           'body'             => file_get_contents('php://input'),
 *           'require_identity' => true,
 *       ]);
 *       // $result->agentSub, $result->kid, $result->jkt, etc.
 *   } catch (AAuthException $e) {
 *       http_response_code(401);
 *       echo json_encode(['error' => $e->getMessage()]);
 *   }
 *
 * Supports the following Signature-Key schemes (per AAuth SIG-KEY spec):
 *   - jwt        (with optional aa-agent+jwt typ enforcement)
 *   - jwks_uri   (two-step well-known discovery)
 *
 * Not yet supported: hwk, jkt-jwt, x509. Patches welcome.
 */
final class RequestVerifier
{
    /** @var list<string> */
    private array $canonicalAuthorities;
    private JwksFetcher $jwksFetcher;
    private int $createdLeeway;

    /**
     * @param array{
     *   canonical_authorities: list<string>,
     *   jwks_fetcher?: JwksFetcher|null,
     *   created_leeway?: int,
     * } $opts
     */
    public function __construct(array $opts)
    {
        if (!isset($opts['canonical_authorities']) || !is_array($opts['canonical_authorities']) || count($opts['canonical_authorities']) === 0) {
            throw new \InvalidArgumentException(
                'RequestVerifier requires non-empty canonical_authorities (list of host[:port] strings)'
            );
        }
        $this->canonicalAuthorities = array_map('strtolower', $opts['canonical_authorities']);
        $this->jwksFetcher = $opts['jwks_fetcher'] ?? new JwksFetcher();
        $this->createdLeeway = $opts['created_leeway'] ?? 60;
    }

    /**
     * @param array{
     *   method: string,
     *   uri: string,
     *   headers: array<string, string|list<string>>,
     *   body?: string|null,
     *   require_identity?: bool,
     *   expected_token_typ?: string|null,
     * } $req
     *
     * @return VerifyResult
     */
    public function verifyRequest(array $req): VerifyResult
    {
        $method = strtoupper($req['method'] ?? '');
        if ($method === '') {
            throw new MalformedRequestException('missing method');
        }

        $uri = $req['uri'] ?? '';
        if (!is_string($uri) || $uri === '') {
            throw new MalformedRequestException('missing uri');
        }
        $parsed = parse_url($uri);
        if ($parsed === false || !isset($parsed['host'])) {
            throw new MalformedRequestException("malformed uri: $uri");
        }
        $authority = strtolower($parsed['host']);
        if (isset($parsed['port'])) {
            $authority .= ':' . $parsed['port'];
        }
        $path = $parsed['path'] ?? '/';
        $query = $parsed['query'] ?? null;

        $headers = self::normalizeHeaders($req['headers'] ?? []);
        $body = $req['body'] ?? null;
        if ($body === '') {
            $body = null;
        }

        $sigInputHdr = $headers['signature-input'] ?? null;
        $sigHdr      = $headers['signature']       ?? null;
        $sigKeyHdr   = $headers['signature-key']   ?? null;

        if ($sigInputHdr === null || $sigHdr === null || $sigKeyHdr === null) {
            throw new MalformedRequestException('missing one of: Signature-Input, Signature, Signature-Key');
        }

        // 1. Authority check — guard against signed requests being replayed against
        //    a different resource. RFC 9421 §1.4 + AAuth SPEC §10.3.1.
        if (!in_array($authority, $this->canonicalAuthorities, true)) {
            throw new WrongAudienceException(sprintf(
                'request authority %s not in canonical_authorities', $authority
            ));
        }

        // 2. Parse the three headers
        $si = HttpSignatures::parseSignatureInput($sigInputHdr);
        $sg = HttpSignatures::parseSignature($sigHdr);
        $sk = HttpSignatures::parseSignatureKey($sigKeyHdr);

        // 3. Cross-header label consistency (SIG-KEY §3.1)
        if ($si['label'] !== $sg['label'] || $sg['label'] !== $sk['label']) {
            throw new MalformedRequestException(sprintf(
                'signature label mismatch: input=%s sig=%s key=%s',
                $si['label'], $sg['label'], $sk['label']
            ));
        }

        // 4. Freshness — reject signatures older than $createdLeeway
        if (isset($si['params']['created'])) {
            $created = (int)$si['params']['created'];
            $skew = abs(time() - $created);
            if ($skew > $this->createdLeeway) {
                throw new StaleSignatureException(sprintf(
                    'signature created %ds outside leeway window of %ds',
                    $skew, $this->createdLeeway
                ));
            }
        }

        // 5. Resolve the public key based on Signature-Key scheme
        $resolved = $this->resolvePublicKey($sk, $req['expected_token_typ'] ?? 'aa-agent+jwt');

        // 6. Build signature base + verify
        $signatureBase = SignatureBase::build(
            method: $method,
            authority: $authority,
            path: $path,
            query: $query,
            headers: $headers,
            body: $body,
            signatureKeyHeader: $sigKeyHdr,
            coveredComponents: $si['components'],
            signatureParams: HttpSignatures::extractSignatureParams($sigInputHdr)
        );

        $alg = $resolved['alg'];
        $publicKey = $resolved['public'];
        $sigBytes = $sg['signature'];

        if ($alg === 'ES256') {
            if (strlen($sigBytes) !== 64) {
                throw new InvalidSignatureException('ES256 signature must be 64 bytes raw r||s');
            }
            $der = EcdsaWire::rawToDer($sigBytes);
            $ok = openssl_verify($signatureBase, $der, $publicKey, OPENSSL_ALGO_SHA256);
            if ($ok !== 1) {
                throw new InvalidSignatureException('ES256 signature verification failed');
            }
        } elseif ($alg === 'EdDSA') {
            if (!sodium_crypto_sign_verify_detached($sigBytes, $signatureBase, $publicKey)) {
                throw new InvalidSignatureException('Ed25519 signature verification failed');
            }
        } else {
            throw new UnsupportedException("unsupported alg: $alg");
        }

        // 7. require_identity: ensure caller offered an agent identity (jwt/jwks_uri schemes do; hwk doesn't).
        if (!empty($req['require_identity']) && !$resolved['has_identity']) {
            throw new MalformedRequestException(
                'require_identity=true but Signature-Key scheme is anonymous (' . $sk['scheme'] . ')'
            );
        }

        return new VerifyResult(
            agentSub: $resolved['claims']['sub'] ?? null,
            agentIss: $resolved['claims']['iss'] ?? null,
            kid: $resolved['kid'],
            alg: $alg,
            scheme: $sk['scheme'],
            jkt: $resolved['jkt'],
            tokenClaims: $resolved['claims'],
            tokenHeader: $resolved['token_header'],
            signatureBase: $signatureBase
        );
    }

    /**
     * @return array{
     *   alg: 'ES256'|'EdDSA',
     *   public: \OpenSSLAsymmetricKey|string,
     *   has_identity: bool,
     *   kid: string|null,
     *   jkt: string|null,
     *   claims: array<string, mixed>,
     *   token_header: array<string, mixed>,
     * }
     */
    private function resolvePublicKey(array $sigKey, string $expectedTokenTyp): array
    {
        $scheme = $sigKey['scheme'];

        if ($scheme === 'jwt') {
            $jwt = $sigKey['params']['jwt'] ?? null;
            if (!is_string($jwt) || $jwt === '') {
                throw new MalformedRequestException('Signature-Key scheme=jwt missing jwt= param');
            }

            // Verify the agent token JWT itself (signed by the agent's
            // long-lived signing key, published at iss/.well-known/{dwk}).
            $verified = JwtVerifier::verify(
                $jwt,
                fn($kid, $iss) => $this->resolveAgentSigningKey($kid, $iss, $sigKey['params']['dwk'] ?? 'aauth-agent.json'),
                ['expected_typ' => $expectedTokenTyp]
            );

            $claims = $verified['payload'];
            $cnf = $claims['cnf'] ?? null;
            if (!is_array($cnf) || !isset($cnf['jwk']) || !is_array($cnf['jwk'])) {
                throw new MalformedRequestException('agent token missing cnf.jwk');
            }

            $cnfKey = JwkConverter::jwkToPublicKey($cnf['jwk']);
            $alg = $cnfKey['type'] === 'ed25519' ? 'EdDSA' : 'ES256';
            $jkt = JwkConverter::jwkThumbprint($cnf['jwk']);

            return [
                'alg' => $alg,
                'public' => $cnfKey['public'],
                'has_identity' => true,
                'kid' => $verified['header']['kid'] ?? null,
                'jkt' => $jkt,
                'claims' => $claims,
                'token_header' => $verified['header'],
            ];
        }

        if ($scheme === 'jwks_uri') {
            $id = $sigKey['params']['id'] ?? null;
            $dwk = $sigKey['params']['dwk'] ?? null;
            $kid = $sigKey['params']['kid'] ?? null;
            if (!is_string($id) || !is_string($dwk) || !is_string($kid)) {
                throw new MalformedRequestException('jwks_uri scheme requires id, dwk, kid');
            }
            $jwks = $this->jwksFetcher->fetchTwoStep($id, $dwk, $kid);
            $jwk = JwksFetcher::findKid($jwks, $kid);
            if ($jwk === null) {
                throw new KeyResolutionException("kid=$kid not found in JWKS for $id");
            }
            $cnvKey = JwkConverter::jwkToPublicKey($jwk);
            $alg = $cnvKey['type'] === 'ed25519' ? 'EdDSA' : 'ES256';
            return [
                'alg' => $alg,
                'public' => $cnvKey['public'],
                'has_identity' => true,
                'kid' => $kid,
                'jkt' => JwkConverter::jwkThumbprint($jwk),
                'claims' => ['sub' => $id, 'iss' => $id],
                'token_header' => ['kid' => $kid],
            ];
        }

        throw new UnsupportedException("Signature-Key scheme not supported in v0.1: $scheme");
    }

    /**
     * @return array<string, mixed>|null
     */
    private function resolveAgentSigningKey(string $kid, ?string $iss, string $dwk): ?array
    {
        if ($iss === null) {
            throw new KeyResolutionException('agent token missing iss claim');
        }
        $jwks = $this->jwksFetcher->fetchTwoStep($iss, $dwk, $kid);
        return JwksFetcher::findKid($jwks, $kid);
    }

    /**
     * @param array<string, string|list<string>> $headers
     * @return array<string, string>
     */
    private static function normalizeHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $key = strtolower((string)$name);
            if (is_array($value)) {
                $out[$key] = implode(', ', $value);
            } else {
                $out[$key] = (string)$value;
            }
        }
        return $out;
    }
}

/**
 * Result of a successful AAuth request verification.
 */
final class VerifyResult
{
    /**
     * @param array<string, mixed> $tokenClaims
     * @param array<string, mixed> $tokenHeader
     */
    public function __construct(
        public readonly ?string $agentSub,
        public readonly ?string $agentIss,
        public readonly ?string $kid,
        public readonly string $alg,
        public readonly string $scheme,
        public readonly ?string $jkt,
        public readonly array $tokenClaims,
        public readonly array $tokenHeader,
        public readonly string $signatureBase,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'agent_sub' => $this->agentSub,
            'agent_iss' => $this->agentIss,
            'kid'       => $this->kid,
            'alg'       => $this->alg,
            'scheme'    => $this->scheme,
            'jkt'       => $this->jkt,
            'capabilities' => $this->tokenClaims['capabilities'] ?? null,
        ];
    }
}
