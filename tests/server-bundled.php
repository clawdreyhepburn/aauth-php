<?php
/**
 * Same as server.php but loads from the single-file bundle instead of src/*.
 * Validates that the bundle works end-to-end.
 */

declare(strict_types=1);

require_once __DIR__ . '/../dist/aauth-bundle.php';

use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/') {
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'lib' => 'aauth-php (bundled)']);
    exit;
}

if ($path === '/whoami') {
    header('Content-Type: application/json');
    $verifier = new RequestVerifier([
        'canonical_authorities' => ['127.0.0.1:9993', 'localhost:9993'],
    ]);
    try {
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        $result = $verifier->verifyRequest([
            'method'  => $_SERVER['REQUEST_METHOD'],
            'uri'     => 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
            'headers' => $headers,
            'body'    => file_get_contents('php://input'),
            'require_identity' => true,
        ]);
        echo json_encode([
            'verified' => true,
            'agent'    => $result->toArray(),
            'served_by' => 'bundle',
        ]);
    } catch (AAuthException $e) {
        http_response_code(401);
        echo json_encode(['verified' => false, 'error' => $e->getMessage()]);
    }
    exit;
}
http_response_code(404);
echo json_encode(['error' => 'not found']);
