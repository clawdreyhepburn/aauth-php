<?php
/**
 * GET /wisdom/situational?moment=morning_under_60f
 *
 * AAuth-verified. Returns a contextual aphorism for the requested moment.
 */

declare(strict_types=1);

require_once __DIR__ . '/../aauth-bundle.php';

use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'wisdom.clawdrey.com';
$absUri = $scheme . '://' . $host . $_SERVER['REQUEST_URI'];

$verifier = new RequestVerifier([
    'canonical_authorities' => ['wisdom.clawdrey.com', $host],
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
    ], JSON_PRETTY_PRINT);
    exit;
}

$wisdom = json_decode((string)file_get_contents(__DIR__ . '/../wisdom.json'), true);
$situations = $wisdom['situational'] ?? [];

$moment = $_GET['moment'] ?? null;
if ($moment === null || !isset($situations[$moment])) {
    http_response_code(400);
    echo json_encode([
        'error' => 'unknown_or_missing_moment',
        'hint' => 'Pass ?moment=<key>. Try one of: ' . implode(', ', array_keys($situations)),
        'available_moments' => array_keys($situations),
    ], JSON_PRETTY_PRINT);
    exit;
}

$pool = $situations[$moment];
$seed = (int) hexdec(substr(hash('sha256', ($result->jkt ?? '') . $moment . gmdate('Y-m-d-H')), 0, 8));
mt_srand($seed);
$idx = mt_rand(0, count($pool) - 1);
$aphorism = $pool[$idx];

echo json_encode([
    'moment' => $moment,
    'aphorism' => $aphorism,
    'served_by' => 'wisdom.clawdrey.com',
    'agent' => [
        'sub' => $result->agentSub,
        'jkt' => $result->jkt,
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
