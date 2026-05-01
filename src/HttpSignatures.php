<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

/**
 * Parsers for the AAuth HTTP signature headers.
 *
 *   - Signature-Input: per RFC 9421, structured-field "Inner List" with params
 *   - Signature: per RFC 9421, structured-field "Byte Sequence"
 *   - Signature-Key: AAuth-specific, structured-field "Item" with params
 *
 * For our purposes we don't need a full SF parser — these headers all follow
 * a tightly constrained shape. We use targeted regex + light hand-parsing
 * so we don't pull in another library.
 */
final class HttpSignatures
{
    /**
     * Parse a Signature-Input header value.
     *
     * Example:
     *   sig=("@method" "@authority" "@path" "signature-key");created=1777630299
     *
     * @return array{label: string, components: list<string>, params: array<string, string|int>}
     */
    public static function parseSignatureInput(string $header): array
    {
        // label = "(" components ")" ";" params
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=\((.*?)\)(.*)$/', $header, $m)) {
            throw new \InvalidArgumentException("malformed Signature-Input: $header");
        }

        $label = $m[1];
        $componentsList = trim($m[2]);
        $paramsTail = $m[3];

        $components = [];
        if ($componentsList !== '') {
            // Components are quoted strings separated by whitespace.
            preg_match_all('/"([^"]*)"/', $componentsList, $cm);
            $components = $cm[1];
        }

        $params = self::parseParams($paramsTail);

        return [
            'label' => $label,
            'components' => $components,
            'params' => $params,
        ];
    }

    /**
     * Parse a Signature header value.
     *
     * Example:
     *   sig=:I6Bjqd...nA==:
     *
     * @return array{label: string, signature: string} where signature is raw bytes
     */
    public static function parseSignature(string $header): array
    {
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=:([^:]*):$/', $header, $m)) {
            throw new \InvalidArgumentException("malformed Signature header: $header");
        }
        $label = $m[1];
        $b64 = $m[2];
        $raw = base64_decode($b64, true);
        if ($raw === false) {
            throw new \InvalidArgumentException('Signature header has invalid base64');
        }
        return ['label' => $label, 'signature' => $raw];
    }

    /**
     * Parse a Signature-Key header value.
     *
     * Example schemes (per AAuth SIG-KEY spec):
     *   sig=jwt;jwt="eyJhbGc..."
     *   sig=jwks_uri;id="https://example.com";dwk="aauth-agent.json";kid="x"
     *   sig=hwk;jwk="{...}"
     *   sig=jkt-jwt;jwt="..."
     *
     * @return array{label: string, scheme: string, params: array<string, string>}
     */
    public static function parseSignatureKey(string $header): array
    {
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=([A-Za-z][A-Za-z0-9_-]*)(.*)$/', $header, $m)) {
            throw new \InvalidArgumentException("malformed Signature-Key: $header");
        }
        $label = $m[1];
        $scheme = $m[2];
        $paramsTail = $m[3];

        return [
            'label' => $label,
            'scheme' => $scheme,
            'params' => self::parseParams($paramsTail, asString: true),
        ];
    }

    /**
     * Parse a parameter tail like ;a=1;b="x";c=token. Values are either
     * tokens (returned as-is, integer if numeric and $asString is false)
     * or quoted strings (returned without the quotes).
     *
     * @return array<string, string|int>
     */
    private static function parseParams(string $tail, bool $asString = false): array
    {
        $params = [];
        // Split on `;` not preceded by `\` (we don't actually do escape handling
        // per RFC 8941, but our headers don't use embedded semicolons so it's fine).
        $pieces = array_filter(array_map('trim', explode(';', $tail)));
        foreach ($pieces as $piece) {
            if ($piece === '') continue;
            if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)\s*(?:=\s*(.*))?$/', $piece, $pm)) {
                throw new \InvalidArgumentException("malformed param: $piece");
            }
            $name = $pm[1];
            $rawVal = $pm[2] ?? '';
            $value = self::parseParamValue($rawVal, $asString);
            $params[$name] = $value;
        }
        return $params;
    }

    /**
     * @return string|int
     */
    private static function parseParamValue(string $raw, bool $asString)
    {
        $raw = trim($raw);
        if ($raw === '') {
            return $asString ? '' : 1;  // bare boolean true → 1
        }
        // Quoted string?
        if (strlen($raw) >= 2 && $raw[0] === '"' && $raw[strlen($raw) - 1] === '"') {
            $inner = substr($raw, 1, -1);
            // Per RFC 8941 quoted strings can contain \" and \\ escapes.
            return str_replace(['\\\\', '\\"'], ['\\', '"'], $inner);
        }
        // Numeric?
        if (!$asString && preg_match('/^-?\d+$/', $raw)) {
            return (int)$raw;
        }
        // Token / unquoted bareword
        return $raw;
    }

    /**
     * Re-serialize a Signature-Input value's "params section" — i.e. the part
     * after the components list — exactly as the signer would have written it.
     *
     * Used to extract the @signature-params trailer for the signature base.
     *
     * In practice we don't re-serialize: we slice the original header. This
     * helper is here for tests and explicit re-construction.
     */
    public static function extractSignatureParams(string $signatureInputHeader): string
    {
        // Strip "<label>=" prefix; return the rest verbatim.
        if (!preg_match('/^([A-Za-z][A-Za-z0-9_-]*)=(.*)$/s', $signatureInputHeader, $m)) {
            throw new \InvalidArgumentException("malformed Signature-Input: $signatureInputHeader");
        }
        return $m[2];
    }
}
