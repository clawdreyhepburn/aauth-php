<?php

declare(strict_types=1);

/**
 * Self-contained test runner for EcdsaWire. No PHPUnit dependency — keeping
 * the build story simple. Run with: php tests/EcdsaWireTest.php
 */

require_once __DIR__ . '/../src/EcdsaWire.php';

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
        echo "      expected: " . bin2hex((string)$expected) . "\n";
        echo "      actual:   " . bin2hex((string)$actual) . "\n";
    }
}

function assertThrows(callable $fn, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    try {
        $fn();
        $failed[] = $label;
        echo "  ✗ $label (no exception raised)\n";
    } catch (\Throwable $e) {
        $passed++;
        echo "  ✓ $label\n";
    }
}

echo "EcdsaWire tests\n";
echo "===============\n\n";

// 1. round-trip with random P-256-shaped data
echo "Round-trip tests:\n";
for ($i = 0; $i < 100; $i++) {
    $raw = random_bytes(64);
    $der = EcdsaWire::rawToDer($raw);
    $back = EcdsaWire::derToRaw($der);
    assertEq($raw, $back, "round-trip random #$i");
}

// 2. specific edge cases
echo "\nEdge cases:\n";

// All-zero r and s — pathological but well-defined
$zero = str_repeat("\x00", 64);
$derZero = EcdsaWire::rawToDer($zero);
$backZero = EcdsaWire::derToRaw($derZero);
assertEq($zero, $backZero, 'all-zero r||s round-trip');

// High bit set in both r and s — must be padded with 0x00
$highBit = str_repeat("\xFF", 64);
$derHigh = EcdsaWire::rawToDer($highBit);
// Should be: 30 46 02 21 00 FF...FF (33 bytes) 02 21 00 FF...FF (33 bytes)
//           = 0x30 (seq) 0x46 (len 70) [02 21 00 + 32xFF] [02 21 00 + 32xFF]
$expectedHigh = "\x30\x46" . "\x02\x21\x00" . str_repeat("\xFF", 32) . "\x02\x21\x00" . str_repeat("\xFF", 32);
assertEq($expectedHigh, $derHigh, 'high-bit r and s — DER padded with 0x00');
$backHigh = EcdsaWire::derToRaw($derHigh);
assertEq($highBit, $backHigh, 'high-bit r and s round-trip');

// One leading zero byte in r — common case for ~1/256 signatures
// raw: 00 r2..r32 || s1..s32  → DER drops the leading 0x00 (only 31 bytes for r)
$leadZero = "\x00" . random_bytes(31) . random_bytes(32);
$derLZ = EcdsaWire::rawToDer($leadZero);
$backLZ = EcdsaWire::derToRaw($derLZ);
assertEq($leadZero, $backLZ, 'leading-zero r round-trip');

// 3. error cases
echo "\nError cases:\n";
assertThrows(function () { EcdsaWire::rawToDer(str_repeat("\x00", 63)); }, 'rawToDer rejects 63-byte input');
assertThrows(function () { EcdsaWire::rawToDer(str_repeat("\x00", 65)); }, 'rawToDer rejects 65-byte input');
assertThrows(function () { EcdsaWire::derToRaw(''); }, 'derToRaw rejects empty input');
assertThrows(function () { EcdsaWire::derToRaw("\x31\x00"); }, 'derToRaw rejects non-SEQUENCE tag');

// 4. real signature from our TS interop test (captured during the Posta interop run)
// signature was: I6Bjqd/jkjDA+KbvbFjlNoVonUyT0ZtynlwgYPr6FGKt74e/XydK8YFrFvVXrsHEv58vqqrQ1GQ4azslszjonA==
echo "\nReal-world signature from TS interop test:\n";
$realRaw = base64_decode('I6Bjqd/jkjDA+KbvbFjlNoVonUyT0ZtynlwgYPr6FGKt74e/XydK8YFrFvVXrsHEv58vqqrQ1GQ4azslszjonA==');
echo "  raw length: " . strlen($realRaw) . " bytes\n";
$realDer = EcdsaWire::rawToDer($realRaw);
echo "  DER length: " . strlen($realDer) . " bytes\n";
echo "  DER hex:    " . bin2hex($realDer) . "\n";
$realBack = EcdsaWire::derToRaw($realDer);
assertEq($realRaw, $realBack, 'real TS-signed P-256 signature round-trip');

// 5. cross-check with OpenSSL: build a known signature in DER, raw-convert,
//    then verify via openssl_verify expecting DER. Round-trip through OpenSSL.
echo "\nCross-check with OpenSSL:\n";
// Generate an EC key, sign something, get DER, convert to raw, convert back, verify.
$privKey = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name'       => 'prime256v1',
]);
if ($privKey === false) {
    echo "  ! could not generate EC key (openssl ext issue?), skipping\n";
} else {
    $msg = "hello aauth-php";
    openssl_sign($msg, $derSig, $privKey, OPENSSL_ALGO_SHA256);
    $details = openssl_pkey_get_details($privKey);
    $pub = openssl_pkey_get_public($details['key']);

    $rawSig = EcdsaWire::derToRaw($derSig);
    assertEq(64, strlen($rawSig), 'raw signature is 64 bytes');

    $rebuiltDer = EcdsaWire::rawToDer($rawSig);
    $verifyOriginal = openssl_verify($msg, $derSig, $pub, OPENSSL_ALGO_SHA256);
    $verifyRebuilt  = openssl_verify($msg, $rebuiltDer, $pub, OPENSSL_ALGO_SHA256);
    assertEq(1, $verifyOriginal, 'OpenSSL verifies original DER signature');
    assertEq(1, $verifyRebuilt, 'OpenSSL verifies signature rebuilt via raw round-trip');
}

echo "\n===============\n";
echo "Tests: $tests, Passed: $passed, Failed: " . count($failed) . "\n";
if (count($failed) > 0) {
    echo "Failed:\n";
    foreach ($failed as $f) echo "  - $f\n";
    exit(1);
}
echo "All passed.\n";
