<?php
/**
 * Integration test resource server. Run with:
 *   php -S 127.0.0.1:9992 tests/server.php
 *
 * GET /            → health
 * GET /whoami      → AAuth-verified, returns claims
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/RequestVerifier.php';

use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/') {
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'lib' => 'aauth-php v0.1.0', 'host' => $_SERVER['HTTP_HOST']]);
    exit;
}

if ($path === '/whoami') {
    header('Content-Type: application/json');
    $verifier = new RequestVerifier([
        'canonical_authorities' => ['127.0.0.1:9992', 'localhost:9992'],
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
        ], JSON_PRETTY_PRINT);
    } catch (AAuthException $e) {
        http_response_code(401);
        echo json_encode([
            'verified' => false,
            'error_class' => (new ReflectionClass($e))->getShortName(),
            'error' => $e->getMessage(),
        ], JSON_PRETTY_PRINT);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode([
            'verified' => false,
            'error_class' => (new ReflectionClass($e))->getShortName(),
            'error' => $e->getMessage(),
        ]);
    }
    exit;
}

http_response_code(404);
echo json_encode(['error' => 'not found']);
