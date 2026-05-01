<?php
/**
 * Lint every ```php code block in the project's markdown docs.
 *
 * Catches the cookbook drifting out of sync with the public API: if a
 * recipe no longer parses on the supported PHP versions, CI fails.
 *
 * Usage:
 *   php scripts/lint-doc-snippets.php
 */

declare(strict_types=1);

$root = dirname(__DIR__);

$files = [
    "$root/README.md",
    "$root/docs/COOKBOOK.md",
];

$tmp = tempnam(sys_get_temp_dir(), 'snippet-') . '.php';

$totalBlocks = 0;
$failures = [];

foreach ($files as $file) {
    if (!is_file($file)) {
        echo "MISSING: $file\n";
        exit(1);
    }
    $md = (string)file_get_contents($file);
    preg_match_all('/```php\n(.*?)\n```/s', $md, $m);

    $rel = ltrim(str_replace($root, '', $file), '/');
    foreach ($m[1] as $i => $code) {
        $totalBlocks++;
        file_put_contents($tmp, $code);
        $out = (string)shell_exec('php -l ' . escapeshellarg($tmp) . ' 2>&1');
        if (strpos($out, 'No syntax errors') === false) {
            $failures[] = "$rel block #$i\n" . trim($out);
        }
    }
}

@unlink($tmp);

if (!empty($failures)) {
    echo "Doc snippet lint FAILED:\n\n";
    foreach ($failures as $f) {
        echo $f . "\n\n";
    }
    exit(1);
}

echo "Linted $totalBlocks PHP code block(s) across " . count($files) . " doc file(s). All clean. ✓\n";
