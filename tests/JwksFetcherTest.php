<?php
/**
 * Tests for JwksFetcher's safety properties. We don't make real HTTPS calls
 * here; we just check the gates that fire before any network IO.
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/JwksFetcher.php';

use Clawdrey\AAuth\JwksFetcher;
use Clawdrey\AAuth\KeyResolutionException;

$tests = 0;
$passed = 0;
$failed = [];

function jfAssertThrowsContains(callable $fn, string $needle, string $label): void {
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

function jfAssertTrue(bool $cond, string $label): void {
    global $tests, $passed, $failed;
    $tests++;
    if ($cond) { $passed++; echo "  ✓ $label\n"; }
    else { $failed[] = $label; echo "  ✗ $label\n"; }
}

echo "JwksFetcher safety tests\n========================\n\n";

$tmpDir = sys_get_temp_dir() . '/aauth-jwks-test-' . bin2hex(random_bytes(4));

// Default: HTTPS only
echo "Scheme enforcement (default):\n";
$f = new JwksFetcher(['cache_dir' => $tmpDir]);

jfAssertThrowsContains(
    fn() => $f->fetchJson('http://example.test/jwks.json'),
    'insecure scheme',
    'http:// JWKS rejected by default'
);

jfAssertThrowsContains(
    fn() => $f->fetchJson('ftp://example.test/jwks.json'),
    'insecure scheme',
    'ftp:// JWKS rejected by default'
);

jfAssertThrowsContains(
    fn() => $f->fetchJson('file:///etc/passwd'),
    'insecure scheme',
    'file:// JWKS rejected by default'
);

jfAssertThrowsContains(
    fn() => $f->fetchJson('javascript:alert(1)'),
    'insecure scheme',
    'javascript: JWKS rejected by default'
);

jfAssertThrowsContains(
    fn() => $f->fetchJson('not-a-url'),
    'insecure scheme',
    'malformed URL rejected by default'
);

// Two-step rejects too
echo "\nTwo-step also enforces scheme:\n";
jfAssertThrowsContains(
    fn() => $f->fetchTwoStep('http://example.test', 'aauth-agent.json'),
    'insecure scheme',
    'two-step rejects http issuer'
);

// Explicit opt-in for tests / fixtures
echo "\nallow_insecure_scheme=true opens http only:\n";
$lax = new JwksFetcher([
    'cache_dir' => $tmpDir,
    'allow_insecure_scheme' => true,
]);

// We won't actually make the call; we just want to see that the scheme
// gate no longer fires. We expect a different error when the actual
// curl call fails (no server listening / no DNS), not the scheme one.
try {
    $lax->fetchJson('http://127.0.0.1:1/never-listens.json');
    jfAssertTrue(false, 'lax http call did not fail (unexpected)');
} catch (\Throwable $e) {
    $msg = $e->getMessage();
    $isSchemeError = stripos($msg, 'insecure scheme') !== false;
    jfAssertTrue(!$isSchemeError, 'http with allow_insecure_scheme passes scheme gate');
}

// Even with the opt-in, file://, ftp://, javascript: are still rejected
jfAssertThrowsContains(
    fn() => $lax->fetchJson('file:///etc/passwd'),
    'insecure scheme',
    'file:// still rejected even with allow_insecure_scheme'
);

jfAssertThrowsContains(
    fn() => $lax->fetchJson('ftp://example.test/jwks.json'),
    'insecure scheme',
    'ftp:// still rejected even with allow_insecure_scheme'
);

// Cache dir is created
jfAssertTrue(is_dir($tmpDir), 'cache dir auto-created');

// findKid logic
echo "\nfindKid:\n";
$jwks = ['keys' => [
    ['kid' => 'a', 'kty' => 'EC'],
    ['kid' => 'b', 'kty' => 'OKP'],
    ['kid' => 'c', 'kty' => 'EC'],
]];
jfAssertTrue(JwksFetcher::findKid($jwks, 'a')['kty'] === 'EC',  'findKid finds first');
jfAssertTrue(JwksFetcher::findKid($jwks, 'b')['kty'] === 'OKP', 'findKid finds middle');
jfAssertTrue(JwksFetcher::findKid($jwks, 'c')['kty'] === 'EC',  'findKid finds last');
jfAssertTrue(JwksFetcher::findKid($jwks, 'missing') === null,   'findKid returns null when absent');

// Cleanup
@array_map('unlink', glob("$tmpDir/*") ?: []);
@rmdir($tmpDir);

echo "\n========================\n";
echo "Tests: $tests, Passed: $passed, Failed: " . count($failed) . "\n";
if (count($failed) > 0) { foreach ($failed as $f) echo "  - $f\n"; exit(1); }
echo "All passed.\n";
