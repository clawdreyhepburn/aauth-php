<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

/**
 * Build the RFC 9421 signature base string that the signer hashes-and-signs.
 *
 * The base is a newline-separated list of "<component-id>: <value>" lines,
 * where component-id is either a derived component (@method, @authority,
 * @path, @query, @signature-params) or a lowercase HTTP header name. The
 * final line is always "@signature-params".
 *
 * This matches the construction in `aauth_signing.signing.build_signature_base`
 * (Posta's Python lib) and `@aauth/mcp-resource`'s buildSignatureBase
 * (Hardt's TS lib) — both of which ultimately defer to RFC 9421 §2.5.
 */
final class SignatureBase
{
    /**
     * @param array<string, string> $headers       lowercase keys
     * @param list<string>          $coveredComponents components in the order specified by Signature-Input
     * @param string                $signatureParams the part of Signature-Input after "<label>="
     */
    public static function build(
        string $method,
        string $authority,
        string $path,
        ?string $query,
        array $headers,
        ?string $body,
        string $signatureKeyHeader,
        array $coveredComponents,
        string $signatureParams
    ): string {
        $lowerHeaders = [];
        foreach ($headers as $k => $v) {
            $lowerHeaders[strtolower($k)] = $v;
        }
        // signature-key isn't always present in $headers (callers may pass
        // it separately); ensure it's available for component resolution.
        $lowerHeaders['signature-key'] = $signatureKeyHeader;

        $lines = [];
        foreach ($coveredComponents as $component) {
            $lines[] = sprintf(
                '"%s": %s',
                $component,
                self::resolveComponent(
                    $component,
                    $method,
                    $authority,
                    $path,
                    $query,
                    $lowerHeaders,
                    $body
                )
            );
        }
        $lines[] = '"@signature-params": ' . $signatureParams;

        return implode("\n", $lines);
    }

    /**
     * @param array<string, string> $lowerHeaders
     */
    private static function resolveComponent(
        string $component,
        string $method,
        string $authority,
        string $path,
        ?string $query,
        array $lowerHeaders,
        ?string $body
    ): string {
        switch ($component) {
            case '@method':
                return strtoupper($method);
            case '@authority':
                return strtolower($authority);
            case '@path':
                return $path;
            case '@query':
                if ($query === null || $query === '') {
                    throw new \InvalidArgumentException('@query covered but query string is empty');
                }
                return '?' . $query;
            case '@target-uri':
                $u = $path;
                if ($query !== null && $query !== '') {
                    $u .= '?' . $query;
                }
                return $u;
            default:
                if (str_starts_with($component, '@')) {
                    throw new \InvalidArgumentException("unsupported derived component: $component");
                }
                $key = strtolower($component);
                if (!isset($lowerHeaders[$key])) {
                    throw new \InvalidArgumentException("missing header for covered component: $component");
                }
                // RFC 9421 §2.1 says: trim leading/trailing whitespace; collapse internal
                // obs-fold whitespace. Simple `trim` covers our cases.
                return trim($lowerHeaders[$key]);
        }
    }
}
