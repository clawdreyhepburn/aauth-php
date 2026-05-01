<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/JwkConverter.php';
require_once __DIR__ . '/../src/EcdsaWire.php';

use Clawdrey\AAuth\JwkConverter;
use Clawdrey\AAuth\EcdsaWire;

$tests = 0;
$passed = 0;
$failed = [];

function assertEq($expected, $actual, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    if ($expected === $actual) {
        $passed++;
        echo "  ✓ $label\n";
    } else {
        $failed[] = $label;
        echo "  ✗ $label\n";
        echo "      expected: " . var_export($expected, true) . "\n";
        echo "      actual:   " . var_export($actual, true) . "\n";
    }
}

function assertTrue(bool $cond, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    if ($cond) {
        $passed++;
        echo "  ✓ $label\n";
    } else {
        $failed[] = $label;
        echo "  ✗ $label\n";
    }
}

function assertThrows(callable $fn, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    try { $fn(); $failed[] = $label; echo "  ✗ $label (no exception)\n"; }
    catch (\Throwable $e) { $passed++; echo "  ✓ $label\n"; }
}

echo "JwkConverter tests\n==================\n\n";

// ----------------------------------------------------------------------
// 1. Ed25519: generate a keypair via libsodium, export as JWK, import,
//    sign+verify roundtrip.
// ----------------------------------------------------------------------
echo "Ed25519:\n";
$keypair = sodium_crypto_sign_keypair();
$privKey = sodium_crypto_sign_secretkey($keypair);
$pubKey = sodium_crypto_sign_publickey($keypair);

$ed25519Jwk = [
    'kty' => 'OKP',
    'crv' => 'Ed25519',
    'x'   => JwkConverter::base64UrlEncode($pubKey),
];
$converted = JwkConverter::jwkToPublicKey($ed25519Jwk);
assertEq('ed25519', $converted['type'], 'Ed25519 JWK → ed25519 type');
assertEq($pubKey, $converted['public'], 'Ed25519 public bytes preserved');

// Sign-and-verify round-trip
$msg = 'hello from aauth-php Ed25519 test';
$sig = sodium_crypto_sign_detached($msg, $privKey);
$ok = sodium_crypto_sign_verify_detached($sig, $msg, $converted['public']);
assertTrue($ok, 'Ed25519 sign/verify round-trip via converted key');

// ----------------------------------------------------------------------
// 2. P-256: same idea via OpenSSL.
// ----------------------------------------------------------------------
echo "\nP-256:\n";
$ec = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name'       => 'prime256v1',
]);
if ($ec === false) {
    echo "  ! could not generate EC key, skipping P-256 tests\n";
} else {
    $details = openssl_pkey_get_details($ec);

    // openssl_pkey_get_details for an EC key returns ec.x/ec.y as raw bytes.
    $rawX = $details['ec']['x'];
    $rawY = $details['ec']['y'];
    assertEq(32, strlen($rawX), 'raw x is 32 bytes');
    assertEq(32, strlen($rawY), 'raw y is 32 bytes');

    $p256Jwk = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => JwkConverter::base64UrlEncode($rawX),
        'y'   => JwkConverter::base64UrlEncode($rawY),
    ];

    $converted = JwkConverter::jwkToPublicKey($p256Jwk);
    assertEq('ecdsa-p256', $converted['type'], 'P-256 JWK → ecdsa-p256 type');
    assertTrue($converted['public'] instanceof \OpenSSLAsymmetricKey, 'returned public is OpenSSLAsymmetricKey');

    // Sign with our generated key, verify with the JWK-converted key
    $msg = 'hello from aauth-php P-256 test';
    openssl_sign($msg, $derSig, $ec, OPENSSL_ALGO_SHA256);
    $verified = openssl_verify($msg, $derSig, $converted['public'], OPENSSL_ALGO_SHA256);
    assertEq(1, $verified, 'P-256 sign with priv / verify with JWK-converted pub');

    // Verify the same signature in raw r||s form, after our EcdsaWire conversion
    $rawSig = EcdsaWire::derToRaw($derSig);
    $rebuiltDer = EcdsaWire::rawToDer($rawSig);
    $verified2 = openssl_verify($msg, $rebuiltDer, $converted['public'], OPENSSL_ALGO_SHA256);
    assertEq(1, $verified2, 'P-256 verify after r||s round-trip');
}

// ----------------------------------------------------------------------
// 3. Real public key from clawdrey.com JWKS — verify the JWK we publish
//    actually loads. This is the exact key our TS agent uses.
// ----------------------------------------------------------------------
echo "\nReal clawdrey.com JWK:\n";
$realJwk = [
    'kty' => 'EC',
    'crv' => 'P-256',
    'x'   => 'sslf8sodWtLQQzte7TqLv9Xve5Z9noMQGdgAJguKJnc',
    'y'   => 'RjvnYdz2ENAUrUTWMoCVF7IRjLtuUMFBLjTTpFP9O0k',
];
$converted = JwkConverter::jwkToPublicKey($realJwk);
assertEq('ecdsa-p256', $converted['type'], 'real clawdrey.com JWK loads as P-256');
assertTrue($converted['public'] instanceof \OpenSSLAsymmetricKey, 'real key is loadable OpenSSL key');

// ----------------------------------------------------------------------
// 4. Thumbprint per RFC 7638
// ----------------------------------------------------------------------
echo "\nRFC 7638 thumbprints:\n";
// Use the example from the RFC §3.1
$rfcExample = [
    'kty' => 'RSA',
    'n'   => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
    'e'   => 'AQAB',
];
// We don't support RSA, so this should throw — but the example demonstrates
// that the canonicalization is well-defined.
assertThrows(function () use ($rfcExample) { JwkConverter::jwkThumbprint($rfcExample); }, 'thumbprint rejects unsupported kty');

// Real thumbprint test: take an Ed25519 JWK, compute thumbprint, verify it's
// 256 bits base64url-encoded (43 chars no padding).
$tp = JwkConverter::jwkThumbprint($ed25519Jwk);
assertEq(43, strlen($tp), 'Ed25519 thumbprint is 43 base64url chars');

// ----------------------------------------------------------------------
// 5. Error cases
// ----------------------------------------------------------------------
echo "\nError cases:\n";
assertThrows(function () { JwkConverter::jwkToPublicKey([]); }, 'empty JWK rejected');
assertThrows(function () { JwkConverter::jwkToPublicKey(['kty' => 'RSA', 'n' => 'x', 'e' => 'AQAB']); }, 'RSA JWK rejected');
assertThrows(function () { JwkConverter::jwkToPublicKey(['kty' => 'EC', 'crv' => 'P-384', 'x' => 'a', 'y' => 'b']); }, 'P-384 rejected');
assertThrows(function () { JwkConverter::jwkToPublicKey(['kty' => 'OKP', 'crv' => 'Ed25519']); }, 'Ed25519 missing x rejected');
assertThrows(function () { JwkConverter::jwkToPublicKey(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => JwkConverter::base64UrlEncode(str_repeat('a', 16))]); }, 'Ed25519 wrong-length x rejected');
assertThrows(function () { JwkConverter::jwkToPublicKey(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'short', 'y' => 'short']); }, 'P-256 wrong-length x/y rejected');

echo "\n==================\n";
echo "Tests: $tests, Passed: $passed, Failed: " . count($failed) . "\n";
if (count($failed) > 0) {
    foreach ($failed as $f) echo "  - $f\n";
    exit(1);
}
echo "All passed.\n";
