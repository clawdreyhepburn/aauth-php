<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

require_once __DIR__ . '/AAuthException.php';

/**
 * Default JWKS fetcher with file-based caching, suitable for shared hosting.
 *
 * AAuth's two-step discovery (per SIG-KEY §3.5):
 *   1. GET {id}/.well-known/{dwk}    → metadata document
 *   2. extract jwks_uri from metadata
 *   3. GET jwks_uri                  → JWKS
 *
 * This is the bottleneck on a cold-start PHP deployment: each request
 * triggers two HTTPS hops to the agent's domain. We cache aggressively
 * (default 1 hour) to amortize.
 *
 * Cache files live in a directory you control. We name them by SHA-256 of
 * the URL so there's no path-traversal risk.
 */
final class JwksFetcher
{
    /** @var string */
    private string $cacheDir;
    /** @var int */
    private int $defaultTtl;
    /** @var int */
    private int $timeoutMs;
    /** @var bool */
    private bool $verifyTls;
    /** @var bool */
    private bool $allowInsecureScheme;

    /**
     * @param array{
     *   cache_dir?: string|null,
     *   ttl_seconds?: int,
     *   timeout_ms?: int,
     *   verify_tls?: bool,
     *   allow_insecure_scheme?: bool,
     * } $opts
     */
    public function __construct(array $opts = [])
    {
        $this->cacheDir = $opts['cache_dir'] ?? sys_get_temp_dir() . '/aauth-jwks-cache';
        $this->defaultTtl = $opts['ttl_seconds'] ?? 3600;
        $this->timeoutMs = $opts['timeout_ms'] ?? 5000;
        $this->verifyTls = $opts['verify_tls'] ?? true;
        // Off by default: refusing http:// JWKS endpoints is a hard requirement
        // for production deployments. Tests and dev fixtures opt in explicitly.
        $this->allowInsecureScheme = $opts['allow_insecure_scheme'] ?? false;

        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0700, true);
        }
    }

    /**
     * Two-step discovery. Used as the callback for the `jwks_uri` Signature-Key scheme.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function fetchTwoStep(string $id, string $dwk, ?string $kid = null): array
    {
        $wellKnown = rtrim($id, '/') . '/.well-known/' . $dwk;
        $meta = $this->fetchJson($wellKnown);

        $jwksUri = $meta['jwks_uri'] ?? null;
        if (!is_string($jwksUri)) {
            throw new MalformedRequestException("metadata at $wellKnown lacks jwks_uri");
        }

        $jwks = $this->fetchJson($jwksUri);
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new MalformedRequestException("JWKS at $jwksUri lacks keys array");
        }

        return $jwks;
    }

    /**
     * Single-step JWKS fetch. Used directly when caller already has a jwks_uri.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function fetchJwks(string $jwksUri): array
    {
        $jwks = $this->fetchJson($jwksUri);
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new MalformedRequestException("JWKS at $jwksUri lacks keys array");
        }
        return $jwks;
    }

    /**
     * Find a key by kid. Returns null if not present.
     *
     * @param array{keys: list<array<string, mixed>>} $jwks
     * @return array<string, mixed>|null
     */
    public static function findKid(array $jwks, string $kid): ?array
    {
        foreach ($jwks['keys'] as $k) {
            if (($k['kid'] ?? null) === $kid) {
                return $k;
            }
        }
        return null;
    }

    /**
     * Fetch JSON with file-based cache. Cache TTL honors response
     * Cache-Control: max-age= when present.
     *
     * @return array<string, mixed>
     */
    public function fetchJson(string $url): array
    {
        $this->assertSafeScheme($url);
        $cacheFile = $this->cacheDir . '/' . hash('sha256', $url) . '.json';

        if (is_readable($cacheFile)) {
            $cached = json_decode((string)file_get_contents($cacheFile), true);
            if (is_array($cached) && isset($cached['expires_at'], $cached['body'])
                && time() < $cached['expires_at']
                && is_array($cached['body'])
            ) {
                return $cached['body'];
            }
        }

        [$body, $maxAge] = $this->httpGetJson($url);

        $ttl = $maxAge !== null ? min($maxAge, $this->defaultTtl * 4) : $this->defaultTtl;
        @file_put_contents($cacheFile, json_encode([
            'fetched_at' => time(),
            'expires_at' => time() + $ttl,
            'url'        => $url,
            'body'       => $body,
        ]), LOCK_EX);

        return $body;
    }

    /**
     * @return array{0: array<string, mixed>, 1: int|null}
     */
    private function httpGetJson(string $url): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new KeyResolutionException("curl_init failed for $url");
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT_MS     => $this->timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $this->timeoutMs,
            CURLOPT_SSL_VERIFYPEER => $this->verifyTls,
            CURLOPT_SSL_VERIFYHOST => $this->verifyTls ? 2 : 0,
            CURLOPT_HEADER         => true,
            CURLOPT_USERAGENT      => 'aauth-php/0.1 (+https://github.com/clawdreyhepburn/aauth-php)',
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);

        $response = curl_exec($ch);
        if ($response === false) {
            // curl_close() is a no-op since PHP 8.0 and deprecated in 8.5;
            // we rely on GC of $ch when it goes out of scope.
            throw new KeyResolutionException("HTTP fetch failed for $url: " . curl_error($ch));
        }

        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        if ($status < 200 || $status >= 300) {
            throw new KeyResolutionException("HTTP $status for $url");
        }

        $headerStr = (string)substr((string)$response, 0, $headerSize);
        $body = (string)substr((string)$response, $headerSize);

        $maxAge = self::parseMaxAge($headerStr);

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new MalformedRequestException("non-JSON or non-object response from $url");
        }
        return [$decoded, $maxAge];
    }

    private static function parseMaxAge(string $headerStr): ?int
    {
        if (preg_match('/^cache-control:\s*[^\r\n]*max-age\s*=\s*(\d+)/im', $headerStr, $m)) {
            return (int)$m[1];
        }
        return null;
    }

    /**
     * Reject any URL that isn't HTTPS unless the caller has explicitly
     * opted into insecure-scheme fetching (for tests / local fixtures).
     */
    private function assertSafeScheme(string $url): void
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if ($scheme === 'https') {
            return;
        }
        if ($scheme === 'http' && $this->allowInsecureScheme) {
            return;
        }
        throw new KeyResolutionException(
            "refusing to fetch JWKS over insecure scheme '$scheme': $url"
        );
    }
}
