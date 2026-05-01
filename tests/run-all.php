<?php
/**
 * One-shot test runner. Runs every *Test.php in this directory and
 * aggregates pass/fail counts. Exits non-zero if any suite fails.
 *
 * Usage:
 *   php tests/run-all.php
 *   php tests/run-all.php --verbose   (show full output of each suite)
 */

declare(strict_types=1);

$verbose = in_array('--verbose', $argv, true) || in_array('-v', $argv, true);

$tests = glob(__DIR__ . '/*Test.php');
sort($tests);

if (count($tests) === 0) {
    echo "No tests found.\n";
    exit(1);
}

$totalTests = 0;
$totalPassed = 0;
$totalFailed = 0;
$failedSuites = [];

$start = microtime(true);

foreach ($tests as $test) {
    $name = basename($test, '.php');
    echo "=== $name ===\n";

    $output = [];
    $code = 0;
    $cmd = escapeshellcmd(PHP_BINARY) . ' ' . escapeshellarg($test);
    exec($cmd . ' 2>&1', $output, $code);

    $text = implode("\n", $output);

    if ($verbose) {
        echo $text . "\n";
    } else {
        // Show only the summary line(s) — lines that start with "Tests:" or "All passed."
        foreach ($output as $line) {
            if (preg_match('/^Tests:\s+\d+/', $line) || str_starts_with(trim($line), '✗ ') || str_contains($line, 'All passed.')) {
                echo $line . "\n";
            }
        }
    }

    if (preg_match('/Tests:\s+(\d+),\s+Passed:\s+(\d+),\s+Failed:\s+(\d+)/', $text, $m)) {
        $totalTests += (int)$m[1];
        $totalPassed += (int)$m[2];
        $totalFailed += (int)$m[3];
    }

    if ($code !== 0) {
        $failedSuites[] = $name;
        if (!$verbose) {
            echo "  (suite exited with code $code; rerun with --verbose for details)\n";
        }
    }

    echo "\n";
}

$elapsed = number_format(microtime(true) - $start, 2);

echo "================================\n";
echo "Total tests:   $totalTests\n";
echo "Total passed:  $totalPassed\n";
echo "Total failed:  $totalFailed\n";
echo "Time:          {$elapsed}s\n";

if (count($failedSuites) > 0) {
    echo "Failed suites: " . implode(', ', $failedSuites) . "\n";
    exit(1);
}

echo "\nAll suites passed. ✓\n";
