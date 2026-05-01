<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/HttpSignatures.php';
require_once __DIR__ . '/../src/SignatureBase.php';

use Clawdrey\AAuth\HttpSignatures;
use Clawdrey\AAuth\SignatureBase;

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
        echo "      expected:\n" . prefixLines((string)$expected, '          | ') . "\n";
        echo "      actual:\n"   . prefixLines((string)$actual, '          | ') . "\n";
    }
}

function prefixLines(string $s, string $p): string {
    return $p . str_replace("\n", "\n$p", $s);
}

echo "HttpSignatures + SignatureBase tests\n";
echo "=====================================\n\n";

// ----------------------------------------------------------------------
// 1. Header parsing
// ----------------------------------------------------------------------
echo "Header parsing:\n";

$si = HttpSignatures::parseSignatureInput(
    'sig=("@method" "@authority" "@path" "signature-key");created=1777630299'
);
assertEq('sig', $si['label'], 'parseSignatureInput label');
assertEq(['@method', '@authority', '@path', 'signature-key'], $si['components'], 'parseSignatureInput components');
assertEq(1777630299, $si['params']['created'], 'parseSignatureInput created param (int)');

$sig = HttpSignatures::parseSignature('sig=:I6Bjqd/jkjDA+KbvbFjlNoVonUyT0ZtynlwgYPr6FGKt74e/XydK8YFrFvVXrsHEv58vqqrQ1GQ4azslszjonA==:');
assertEq('sig', $sig['label'], 'parseSignature label');
assertEq(64, strlen($sig['signature']), 'parseSignature returns 64 raw bytes for P-256');

$sk = HttpSignatures::parseSignatureKey('sig=jwt;jwt="eyJhbGc"');
assertEq('sig', $sk['label'], 'parseSignatureKey label');
assertEq('jwt', $sk['scheme'], 'parseSignatureKey scheme');
assertEq('eyJhbGc', $sk['params']['jwt'], 'parseSignatureKey jwt param');

$sk2 = HttpSignatures::parseSignatureKey('sig=jwks_uri;id="https://x.com";dwk="d.json";kid="k1"');
assertEq('jwks_uri', $sk2['scheme'], 'parseSignatureKey jwks_uri scheme');
assertEq('https://x.com', $sk2['params']['id'], 'parseSignatureKey id');
assertEq('d.json', $sk2['params']['dwk'], 'parseSignatureKey dwk');
assertEq('k1', $sk2['params']['kid'], 'parseSignatureKey kid');

// ----------------------------------------------------------------------
// 2. Build signature base for a known input + compare against Python
//    aauth_signing's reference output.
// ----------------------------------------------------------------------
echo "\nSignature-base construction:\n";

$fixture = json_decode(file_get_contents(__DIR__ . '/fixtures/ts-signed.json'), true);
foreach ($fixture['captures'] as $i => $c) {
    $sigInput = $c['headers']['signature-input'];
    $parsed = HttpSignatures::parseSignatureInput($sigInput);

    // Reconstruct the URL pieces
    $url = parse_url('http://127.0.0.1:19999' . $c['url']);
    $query = $url['query'] ?? null;
    $path = $url['path'] ?? '/';

    $sigKeyHeader = $c['headers']['signature-key'];

    $params = HttpSignatures::extractSignatureParams($sigInput);
    $base = SignatureBase::build(
        method: $c['method'],
        authority: $c['headers']['host'] ?? $url['host'] . ':' . ($url['port'] ?? 80),
        path: $path,
        query: $query,
        headers: $c['headers'],
        body: $c['body_text'] ?: null,
        signatureKeyHeader: $sigKeyHeader,
        coveredComponents: $parsed['components'],
        signatureParams: $params
    );

    echo "  capture #$i ({$c['method']} {$c['url']}):\n";
    echo prefixLines($base, '      ') . "\n";

    // The base must START with each covered component, in order.
    $expected_first_line = sprintf('"%s": %s', $parsed['components'][0], strtoupper($c['method']));
    assertEq(
        $expected_first_line,
        explode("\n", $base)[0],
        "base[#$i] starts with first covered component"
    );

    // The base must END with @signature-params line.
    $lastLine = array_slice(explode("\n", $base), -1)[0];
    assertEq(
        '"@signature-params": ' . $params,
        $lastLine,
        "base[#$i] ends with @signature-params"
    );
}

// ----------------------------------------------------------------------
// 3. The full end-to-end win: take fixture #0, resolve the actual public
//    key from the JWT's cnf.jwk, and verify the signature against the
//    base we just built. If this works, we know our base matches the
//    signer's base byte-for-byte.
// ----------------------------------------------------------------------
echo "\nEnd-to-end verify of TS-signed request via PHP-built base:\n";

require_once __DIR__ . '/../src/JwkConverter.php';
require_once __DIR__ . '/../src/EcdsaWire.php';
use Clawdrey\AAuth\JwkConverter;
use Clawdrey\AAuth\EcdsaWire;

$cap = $fixture['captures'][0];
$sigInputHdr = $cap['headers']['signature-input'];
$sigHdr      = $cap['headers']['signature'];
$sigKeyHdr   = $cap['headers']['signature-key'];

$siParsed = HttpSignatures::parseSignatureInput($sigInputHdr);
$sigParsed = HttpSignatures::parseSignature($sigHdr);
$skParsed = HttpSignatures::parseSignatureKey($sigKeyHdr);

assertEq('jwt', $skParsed['scheme'], 'real fixture uses jwt scheme');

// Decode the JWT and pull cnf.jwk
$jwtB64 = $skParsed['params']['jwt'];
[, $payloadB64,] = explode('.', $jwtB64);
$payload = json_decode(JwkConverter::base64UrlDecode($payloadB64), true);
$cnfJwk = $payload['cnf']['jwk'];
echo "  cnf.jwk: kty={$cnfJwk['kty']} crv={$cnfJwk['crv']}\n";

$pub = JwkConverter::jwkToPublicKey($cnfJwk);
assertEq('ecdsa-p256', $pub['type'], 'cnf.jwk loads as P-256');

$url = parse_url('http://127.0.0.1:19999' . $cap['url']);
$base = SignatureBase::build(
    method: $cap['method'],
    authority: $cap['headers']['host'],
    path: $url['path'],
    query: $url['query'] ?? null,
    headers: $cap['headers'],
    body: null,
    signatureKeyHeader: $sigKeyHdr,
    coveredComponents: $siParsed['components'],
    signatureParams: HttpSignatures::extractSignatureParams($sigInputHdr)
);

echo "  signature base ({" . strlen($base) . "} bytes):\n" . prefixLines($base, '      ') . "\n";

$der = EcdsaWire::rawToDer($sigParsed['signature']);
$verified = openssl_verify($base, $der, $pub['public'], OPENSSL_ALGO_SHA256);
assertEq(1, $verified, '⭐ TS-signed request VERIFIES against PHP-built signature base');

// Repeat for the POST capture (different covered components)
echo "\nVerify POST fixture (covers content-type):\n";
$cap2 = $fixture['captures'][2];
$si2 = HttpSignatures::parseSignatureInput($cap2['headers']['signature-input']);
$sg2 = HttpSignatures::parseSignature($cap2['headers']['signature']);
$sk2 = HttpSignatures::parseSignatureKey($cap2['headers']['signature-key']);
$jwt2 = $sk2['params']['jwt'];
[, $pl2,] = explode('.', $jwt2);
$payload2 = json_decode(JwkConverter::base64UrlDecode($pl2), true);
$pub2 = JwkConverter::jwkToPublicKey($payload2['cnf']['jwk']);

$url2 = parse_url('http://127.0.0.1:19999' . $cap2['url']);
$base2 = SignatureBase::build(
    method: $cap2['method'],
    authority: $cap2['headers']['host'],
    path: $url2['path'],
    query: $url2['query'] ?? null,
    headers: $cap2['headers'],
    body: $cap2['body_text'],
    signatureKeyHeader: $cap2['headers']['signature-key'],
    coveredComponents: $si2['components'],
    signatureParams: HttpSignatures::extractSignatureParams($cap2['headers']['signature-input'])
);
echo "  POST base ({" . strlen($base2) . "} bytes):\n" . prefixLines($base2, '      ') . "\n";
$der2 = EcdsaWire::rawToDer($sg2['signature']);
$verified2 = openssl_verify($base2, $der2, $pub2['public'], OPENSSL_ALGO_SHA256);
assertEq(1, $verified2, '⭐ POST TS-signed request VERIFIES against PHP-built signature base');

echo "\n=====================================\n";
echo "Tests: $tests, Passed: $passed, Failed: " . count($failed) . "\n";
if (count($failed) > 0) {
    foreach ($failed as $f) echo "  - $f\n";
    exit(1);
}
echo "All passed.\n";
