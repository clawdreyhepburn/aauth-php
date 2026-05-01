<?php
/**
 * GET /wisdom/foundations
 *
 * AAuth-verified. Returns a random foundational aphorism.
 */

declare(strict_types=1);

require_once __DIR__ . '/../aauth-bundle.php';

use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// Build absolute URI as the verifier wants it (canonical authorities below
// list the acceptable host[:port] values).
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
// DreamHost terminates TLS at the front; X-Forwarded-Proto isn't always set.
// We also explicitly pin to https for the wisdom subdomain.
$host = $_SERVER['HTTP_HOST'] ?? 'wisdom.clawdrey.com';
$absUri = $scheme . '://' . $host . $_SERVER['REQUEST_URI'];

$verifier = new RequestVerifier([
    'canonical_authorities' => [
        'wisdom.clawdrey.com',
        $host, // also accept whatever the request actually arrived as
    ],
]);

try {
    $result = $verifier->verifyRequest([
        'method' => $_SERVER['REQUEST_METHOD'],
        'uri'    => $absUri,
        'headers' => function_exists('getallheaders') ? getallheaders() : [],
        'body'   => file_get_contents('php://input'),
        'require_identity' => true,
    ]);
} catch (AAuthException $e) {
    http_response_code(401);
    header('WWW-Authenticate: AAuth');
    echo json_encode([
        'verified' => false,
        'error_class' => (new ReflectionClass($e))->getShortName(),
        'error' => $e->getMessage(),
        'hint' => 'Sign your request with AAuth. See https://wisdom.clawdrey.com for examples.',
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$wisdomFile = __DIR__ . '/../wisdom.json';
$wisdom = json_decode((string)file_get_contents($wisdomFile), true);
$pool = $wisdom['foundations'] ?? [];
if (count($pool) === 0) {
    http_response_code(503);
    echo json_encode(['error' => 'wisdom corpus unavailable']);
    exit;
}

// Seed the random pick from the JKT thumbprint so the same agent gets
// some consistency between calls (rotates daily). Prevents agents from
// hammering us to dump the corpus, while still feeling alive.
$seed = (int) hexdec(substr(hash('sha256', ($result->jkt ?? '') . gmdate('Y-m-d')), 0, 8));
mt_srand($seed);
$idx = mt_rand(0, count($pool) - 1);
$aphorism = $pool[$idx];

echo json_encode([
    'aphorism' => $aphorism,
    'served_by' => 'wisdom.clawdrey.com',
    'agent' => [
        'sub' => $result->agentSub,
        'iss' => $result->agentIss,
        'jkt' => $result->jkt,
    ],
    'caveat' => 'Aphorisms vary by day and by agent. Bookmark the one that finds you.',
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
