<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

require_once __DIR__ . '/EcdsaWire.php';
require_once __DIR__ . '/JwkConverter.php';

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
