<?php

declare(strict_types=1);

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
