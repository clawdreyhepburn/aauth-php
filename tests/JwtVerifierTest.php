<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/JwtVerifier.php';
require_once __DIR__ . '/../src/JwkConverter.php';

use Clawdrey\AAuth\JwtVerifier;
use Clawdrey\AAuth\JwtException;
use Clawdrey\AAuth\JwkConverter;

$tests = 0;
$passed = 0;
$failed = [];

function assertEq($expected, $actual, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    if ($expected === $actual) { $passed++; echo "  ✓ $label\n"; }
    else {
        $failed[] = $label;
        echo "  ✗ $label\n";
        echo "      expected: " . var_export($expected, true) . "\n";
        echo "      actual:   " . var_export($actual, true) . "\n";
    }
}
function assertTrue(bool $cond, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    if ($cond) { $passed++; echo "  ✓ $label\n"; }
    else { $failed[] = $label; echo "  ✗ $label\n"; }
}
function assertThrowsContains(callable $fn, string $needle, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    try {
        $fn();
        $failed[] = $label;
        echo "  ✗ $label (no exception)\n";
    } catch (\Throwable $e) {
        if (stripos($e->getMessage(), $needle) !== false) { $passed++; echo "  ✓ $label\n"; }
        else { $failed[] = $label; echo "  ✗ $label (wrong msg: {$e->getMessage()})\n"; }
    }
}

echo "JwtVerifier tests\n=================\n\n";

// ----------------------------------------------------------------------
// 1. Real JWT from our TS interop fixture (ES256, aa-agent+jwt)
// ----------------------------------------------------------------------
echo "Real ES256 aa-agent+jwt from TS fixture:\n";

$fixture = json_decode(file_get_contents(__DIR__ . '/fixtures/ts-signed.json'), true);
$sigKey = $fixture['captures'][0]['headers']['signature-key'];
preg_match('/jwt="([^"]+)"/', $sigKey, $m);
$realJwt = $m[1];

// The expected_jwk in the fixture is for the *agent's* signing key, not the cnf.jwk.
// To verify the JWT, we need the agent's published JWK — that's what the issuer
// would publish at clawdrey.com/.well-known/jwks.json.
$agentJwk = $fixture['expected_jwk'];

$result = JwtVerifier::verify(
    $realJwt,
    fn($kid, $iss) => $kid === $agentJwk['kid'] ? $agentJwk : null,
    ['expected_typ' => 'aa-agent+jwt']
);
assertEq('aa-agent+jwt', $result['header']['typ'], 'verified header typ');
assertEq('aauth:openclaw@clawdrey.com', $result['payload']['sub'], 'verified payload sub');
assertEq('https://clawdrey.com', $result['payload']['iss'], 'verified payload iss');
assertTrue(isset($result['payload']['cnf']['jwk']), 'payload contains cnf.jwk');
assertEq('EC', $result['payload']['cnf']['jwk']['kty'], 'cnf.jwk is EC');

// ----------------------------------------------------------------------
// 2. Tampered JWT must fail
// ----------------------------------------------------------------------
echo "\nTampered tokens:\n";

assertThrowsContains(
    function () use ($realJwt, $agentJwk) {
        // flip a bit in the payload
        [$h, $p, $s] = explode('.', $realJwt);
        $rawPayload = JwkConverter::base64UrlDecode($p);
        $rawPayload[10] = chr(ord($rawPayload[10]) ^ 0x01);
        $newP = JwkConverter::base64UrlEncode($rawPayload);
        $tampered = "$h.$newP.$s";
        JwtVerifier::verify(
            $tampered,
            fn($kid, $iss) => $kid === $agentJwk['kid'] ? $agentJwk : null
        );
    },
    'verification failed',
    'tampered payload rejected'
);

assertThrowsContains(
    function () use ($realJwt, $agentJwk) {
        // truncate the signature
        [$h, $p, $s] = explode('.', $realJwt);
        $tampered = "$h.$p." . substr($s, 0, 10);
        JwtVerifier::verify(
            $tampered,
            fn($kid, $iss) => $kid === $agentJwk['kid'] ? $agentJwk : null
        );
    },
    'must be 64',
    'truncated signature rejected with size error'
);

// ----------------------------------------------------------------------
// 3. typ mismatch
// ----------------------------------------------------------------------
echo "\ntyp/iss/aud validation:\n";

assertThrowsContains(
    fn() => JwtVerifier::verify(
        $realJwt,
        fn($kid) => $kid === $agentJwk['kid'] ? $agentJwk : null,
        ['expected_typ' => 'something-else']
    ),
    'typ mismatch',
    'wrong expected_typ rejected'
);

assertThrowsContains(
    fn() => JwtVerifier::verify(
        $realJwt,
        fn($kid) => $kid === $agentJwk['kid'] ? $agentJwk : null,
        ['issuer' => 'https://wrong.example']
    ),
    'iss mismatch',
    'wrong issuer rejected'
);

// ----------------------------------------------------------------------
// 4. Resolver returns wrong key → signature fails
// ----------------------------------------------------------------------
echo "\nWrong-key path:\n";

// Generate an unrelated key
$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
$details = openssl_pkey_get_details($ec);
$wrongJwk = [
    'kty' => 'EC',
    'crv' => 'P-256',
    'x'   => JwkConverter::base64UrlEncode($details['ec']['x']),
    'y'   => JwkConverter::base64UrlEncode($details['ec']['y']),
];

assertThrowsContains(
    fn() => JwtVerifier::verify(
        $realJwt,
        fn($kid) => $wrongJwk
    ),
    'verification failed',
    'wrong public key rejected'
);

// ----------------------------------------------------------------------
// 5. Ed25519 path — round-trip
// ----------------------------------------------------------------------
echo "\nEd25519 round-trip:\n";

$kp = sodium_crypto_sign_keypair();
$priv = sodium_crypto_sign_secretkey($kp);
$pub = sodium_crypto_sign_publickey($kp);

$ed25519Jwk = [
    'kty' => 'OKP',
    'crv' => 'Ed25519',
    'x'   => JwkConverter::base64UrlEncode($pub),
    'kid' => 'test-ed25519',
];

// Build a JWT manually
$header = ['alg' => 'EdDSA', 'typ' => 'aa-agent+jwt', 'kid' => 'test-ed25519'];
$payload = [
    'iss' => 'https://example.test',
    'sub' => 'aauth:test@example.test',
    'iat' => time(),
    'exp' => time() + 600,
];
$h64 = JwkConverter::base64UrlEncode(json_encode($header));
$p64 = JwkConverter::base64UrlEncode(json_encode($payload));
$signingInput = "$h64.$p64";
$sig = sodium_crypto_sign_detached($signingInput, $priv);
$jwt = "$h64.$p64." . JwkConverter::base64UrlEncode($sig);

$result = JwtVerifier::verify(
    $jwt,
    fn($kid) => $kid === 'test-ed25519' ? $ed25519Jwk : null,
    ['expected_typ' => 'aa-agent+jwt']
);
assertEq('aauth:test@example.test', $result['payload']['sub'], 'Ed25519 JWT verifies');

// Tamper Ed25519
assertThrowsContains(
    function () use ($jwt, $ed25519Jwk) {
        $jwt = substr($jwt, 0, -2) . 'AA';  // mangle last 2 chars of signature
        JwtVerifier::verify($jwt, fn($kid) => $ed25519Jwk);
    },
    'verification failed',
    'tampered Ed25519 JWT rejected'
);

// ----------------------------------------------------------------------
// 6. Expiration
// ----------------------------------------------------------------------
echo "\nExpiration:\n";

$expHeader = ['alg' => 'EdDSA', 'typ' => 'test+jwt', 'kid' => 'test-ed25519'];
$expPayload = ['exp' => time() - 1000, 'iat' => time() - 2000];
$h64 = JwkConverter::base64UrlEncode(json_encode($expHeader));
$p64 = JwkConverter::base64UrlEncode(json_encode($expPayload));
$signingInput = "$h64.$p64";
$sig = sodium_crypto_sign_detached($signingInput, $priv);
$expJwt = "$h64.$p64." . JwkConverter::base64UrlEncode($sig);

assertThrowsContains(
    fn() => JwtVerifier::verify($expJwt, fn($kid) => $ed25519Jwk),
    'expired',
    'expired JWT rejected'
);

// ----------------------------------------------------------------------
// 7. Malformed input
// ----------------------------------------------------------------------
echo "\nMalformed input:\n";

assertThrowsContains(fn() => JwtVerifier::verify('not.a.jwt.too.many', fn() => null), '3 parts', 'too-many-parts rejected');
assertThrowsContains(fn() => JwtVerifier::verify('only.two', fn() => null), '3 parts', 'two-parts rejected');
assertThrowsContains(fn() => JwtVerifier::verify('eyJ$$$.foo.bar', fn() => null), 'decode', 'bad base64 rejected');

echo "\n=================\n";
echo "Tests: $tests, Passed: $passed, Failed: " . count($failed) . "\n";
if (count($failed) > 0) { foreach ($failed as $f) echo "  - $f\n"; exit(1); }
echo "All passed.\n";
