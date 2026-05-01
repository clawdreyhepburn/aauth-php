<?php

declare(strict_types=1);

namespace Clawdrey\AAuth;

require_once __DIR__ . '/AAuthException.php';
require_once __DIR__ . '/EcdsaWire.php';
require_once __DIR__ . '/JwkConverter.php';
require_once __DIR__ . '/HttpSignatures.php';
require_once __DIR__ . '/SignatureBase.php';
require_once __DIR__ . '/JwtVerifier.php';
require_once __DIR__ . '/JwksFetcher.php';

/**
 * Top-level AAuth request verifier. The public face of aauth-php.
 *
 * Usage:
 *
 *   $verifier = new RequestVerifier([
 *       'canonical_authorities' => ['wisdom.clawdrey.com'],
 *   ]);
 *
 *   try {
 *       $result = $verifier->verifyRequest([
 *           'method'           => $_SERVER['REQUEST_METHOD'],
 *           'uri'              => 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
 *           'headers'          => getallheaders(),
 *           'body'             => file_get_contents('php://input'),
 *           'require_identity' => true,
 *       ]);
 *       // $result->agentSub, $result->kid, $result->jkt, etc.
 *   } catch (AAuthException $e) {
 *       http_response_code(401);
 *       echo json_encode(['error' => $e->getMessage()]);
 *   }
 *
 * Supports the following Signature-Key schemes (per AAuth SIG-KEY spec):
 *   - jwt        (with optional aa-agent+jwt typ enforcement)
 *   - jwks_uri   (two-step well-known discovery)
 *
 * Not yet supported: hwk, jkt-jwt, x509. Patches welcome.
 */
final class RequestVerifier
{
    /** @var list<string> */
    private array $canonicalAuthorities;
    private JwksFetcher $jwksFetcher;
    private int $createdLeeway;

    /**
     * @param array{
     *   canonical_authorities: list<string>,
     *   jwks_fetcher?: JwksFetcher|null,
     *   created_leeway?: int,
     * } $opts
     */
    public function __construct(array $opts)
    {
        if (!isset($opts['canonical_authorities']) || !is_array($opts['canonical_authorities']) || count($opts['canonical_authorities']) === 0) {
            throw new \InvalidArgumentException(
                'RequestVerifier requires non-empty canonical_authorities (list of host[:port] strings)'
            );
        }
        $this->canonicalAuthorities = array_map('strtolower', $opts['canonical_authorities']);
        $this->jwksFetcher = $opts['jwks_fetcher'] ?? new JwksFetcher();
        $this->createdLeeway = $opts['created_leeway'] ?? 60;
    }

    /**
     * @param array{
     *   method: string,
     *   uri: string,
     *   headers: array<string, string|list<string>>,
     *   body?: string|null,
     *   require_identity?: bool,
     *   expected_token_typ?: string|null,
     * } $req
     *
     * @return VerifyResult
     */
    public function verifyRequest(array $req): VerifyResult
    {
        $method = strtoupper($req['method'] ?? '');
        if ($method === '') {
            throw new MalformedRequestException('missing method');
        }

        $uri = $req['uri'] ?? '';
        if (!is_string($uri) || $uri === '') {
            throw new MalformedRequestException('missing uri');
        }
        $parsed = parse_url($uri);
        if ($parsed === false || !isset($parsed['host'])) {
            throw new MalformedRequestException("malformed uri: $uri");
        }
        $authority = strtolower($parsed['host']);
        if (isset($parsed['port'])) {
            $authority .= ':' . $parsed['port'];
        }
        $path = $parsed['path'] ?? '/';
        $query = $parsed['query'] ?? null;

        $headers = self::normalizeHeaders($req['headers'] ?? []);
        $body = $req['body'] ?? null;
        if ($body === '') {
            $body = null;
        }

        $sigInputHdr = $headers['signature-input'] ?? null;
        $sigHdr      = $headers['signature']       ?? null;
        $sigKeyHdr   = $headers['signature-key']   ?? null;

        if ($sigInputHdr === null || $sigHdr === null || $sigKeyHdr === null) {
            throw new MalformedRequestException('missing one of: Signature-Input, Signature, Signature-Key');
        }

        // 1. Authority check — guard against signed requests being replayed against
        //    a different resource. RFC 9421 §1.4 + AAuth SPEC §10.3.1.
        if (!in_array($authority, $this->canonicalAuthorities, true)) {
            throw new WrongAudienceException(sprintf(
                'request authority %s not in canonical_authorities', $authority
            ));
        }

        // 2. Parse the three headers
        $si = HttpSignatures::parseSignatureInput($sigInputHdr);
        $sg = HttpSignatures::parseSignature($sigHdr);
        $sk = HttpSignatures::parseSignatureKey($sigKeyHdr);

        // 3. Cross-header label consistency (SIG-KEY §3.1)
        if ($si['label'] !== $sg['label'] || $sg['label'] !== $sk['label']) {
            throw new MalformedRequestException(sprintf(
                'signature label mismatch: input=%s sig=%s key=%s',
                $si['label'], $sg['label'], $sk['label']
            ));
        }

        // 4. Freshness — reject signatures older than $createdLeeway
        if (isset($si['params']['created'])) {
            $created = (int)$si['params']['created'];
            $skew = abs(time() - $created);
            if ($skew > $this->createdLeeway) {
                throw new StaleSignatureException(sprintf(
                    'signature created %ds outside leeway window of %ds',
                    $skew, $this->createdLeeway
                ));
            }
        }

        // 5. Resolve the public key based on Signature-Key scheme
        $resolved = $this->resolvePublicKey($sk, $req['expected_token_typ'] ?? 'aa-agent+jwt');

        // 6. Build signature base + verify
        $signatureBase = SignatureBase::build(
            method: $method,
            authority: $authority,
            path: $path,
            query: $query,
            headers: $headers,
            body: $body,
            signatureKeyHeader: $sigKeyHdr,
            coveredComponents: $si['components'],
            signatureParams: HttpSignatures::extractSignatureParams($sigInputHdr)
        );

        $alg = $resolved['alg'];
        $publicKey = $resolved['public'];
        $sigBytes = $sg['signature'];

        if ($alg === 'ES256') {
            if (strlen($sigBytes) !== 64) {
                throw new InvalidSignatureException('ES256 signature must be 64 bytes raw r||s');
            }
            $der = EcdsaWire::rawToDer($sigBytes);
            $ok = openssl_verify($signatureBase, $der, $publicKey, OPENSSL_ALGO_SHA256);
            if ($ok !== 1) {
                throw new InvalidSignatureException('ES256 signature verification failed');
            }
        } elseif ($alg === 'EdDSA') {
            if (!sodium_crypto_sign_verify_detached($sigBytes, $signatureBase, $publicKey)) {
                throw new InvalidSignatureException('Ed25519 signature verification failed');
            }
        } else {
            throw new UnsupportedException("unsupported alg: $alg");
        }

        // 7. require_identity: ensure caller offered an agent identity (jwt/jwks_uri schemes do; hwk doesn't).
        if (!empty($req['require_identity']) && !$resolved['has_identity']) {
            throw new MalformedRequestException(
                'require_identity=true but Signature-Key scheme is anonymous (' . $sk['scheme'] . ')'
            );
        }

        return new VerifyResult(
            agentSub: $resolved['claims']['sub'] ?? null,
            agentIss: $resolved['claims']['iss'] ?? null,
            kid: $resolved['kid'],
            alg: $alg,
            scheme: $sk['scheme'],
            jkt: $resolved['jkt'],
            tokenClaims: $resolved['claims'],
            tokenHeader: $resolved['token_header'],
            signatureBase: $signatureBase
        );
    }

    /**
     * @return array{
     *   alg: 'ES256'|'EdDSA',
     *   public: \OpenSSLAsymmetricKey|string,
     *   has_identity: bool,
     *   kid: string|null,
     *   jkt: string|null,
     *   claims: array<string, mixed>,
     *   token_header: array<string, mixed>,
     * }
     */
    private function resolvePublicKey(array $sigKey, string $expectedTokenTyp): array
    {
        $scheme = $sigKey['scheme'];

        if ($scheme === 'jwt') {
            $jwt = $sigKey['params']['jwt'] ?? null;
            if (!is_string($jwt) || $jwt === '') {
                throw new MalformedRequestException('Signature-Key scheme=jwt missing jwt= param');
            }

            // Verify the agent token JWT itself (signed by the agent's
            // long-lived signing key, published at iss/.well-known/{dwk}).
            $verified = JwtVerifier::verify(
                $jwt,
                fn($kid, $iss) => $this->resolveAgentSigningKey($kid, $iss, $sigKey['params']['dwk'] ?? 'aauth-agent.json'),
                ['expected_typ' => $expectedTokenTyp]
            );

            $claims = $verified['payload'];
            $cnf = $claims['cnf'] ?? null;
            if (!is_array($cnf) || !isset($cnf['jwk']) || !is_array($cnf['jwk'])) {
                throw new MalformedRequestException('agent token missing cnf.jwk');
            }

            $cnfKey = JwkConverter::jwkToPublicKey($cnf['jwk']);
            $alg = $cnfKey['type'] === 'ed25519' ? 'EdDSA' : 'ES256';
            $jkt = JwkConverter::jwkThumbprint($cnf['jwk']);

            return [
                'alg' => $alg,
                'public' => $cnfKey['public'],
                'has_identity' => true,
                'kid' => $verified['header']['kid'] ?? null,
                'jkt' => $jkt,
                'claims' => $claims,
                'token_header' => $verified['header'],
            ];
        }

        if ($scheme === 'jwks_uri') {
            $id = $sigKey['params']['id'] ?? null;
            $dwk = $sigKey['params']['dwk'] ?? null;
            $kid = $sigKey['params']['kid'] ?? null;
            if (!is_string($id) || !is_string($dwk) || !is_string($kid)) {
                throw new MalformedRequestException('jwks_uri scheme requires id, dwk, kid');
            }
            $jwks = $this->jwksFetcher->fetchTwoStep($id, $dwk, $kid);
            $jwk = JwksFetcher::findKid($jwks, $kid);
            if ($jwk === null) {
                throw new KeyResolutionException("kid=$kid not found in JWKS for $id");
            }
            $cnvKey = JwkConverter::jwkToPublicKey($jwk);
            $alg = $cnvKey['type'] === 'ed25519' ? 'EdDSA' : 'ES256';
            return [
                'alg' => $alg,
                'public' => $cnvKey['public'],
                'has_identity' => true,
                'kid' => $kid,
                'jkt' => JwkConverter::jwkThumbprint($jwk),
                'claims' => ['sub' => $id, 'iss' => $id],
                'token_header' => ['kid' => $kid],
            ];
        }

        throw new UnsupportedException("Signature-Key scheme not supported in v0.1: $scheme");
    }

    /**
     * @return array<string, mixed>|null
     */
    private function resolveAgentSigningKey(string $kid, ?string $iss, string $dwk): ?array
    {
        if ($iss === null) {
            throw new KeyResolutionException('agent token missing iss claim');
        }
        $jwks = $this->jwksFetcher->fetchTwoStep($iss, $dwk, $kid);
        return JwksFetcher::findKid($jwks, $kid);
    }

    /**
     * @param array<string, string|list<string>> $headers
     * @return array<string, string>
     */
    private static function normalizeHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $key = strtolower((string)$name);
            if (is_array($value)) {
                $out[$key] = implode(', ', $value);
            } else {
                $out[$key] = (string)$value;
            }
        }
        return $out;
    }
}

/**
 * Result of a successful AAuth request verification.
 */
final class VerifyResult
{
    /**
     * @param array<string, mixed> $tokenClaims
     * @param array<string, mixed> $tokenHeader
     */
    public function __construct(
        public readonly ?string $agentSub,
        public readonly ?string $agentIss,
        public readonly ?string $kid,
        public readonly string $alg,
        public readonly string $scheme,
        public readonly ?string $jkt,
        public readonly array $tokenClaims,
        public readonly array $tokenHeader,
        public readonly string $signatureBase,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'agent_sub' => $this->agentSub,
            'agent_iss' => $this->agentIss,
            'kid'       => $this->kid,
            'alg'       => $this->alg,
            'scheme'    => $this->scheme,
            'jkt'       => $this->jkt,
            'capabilities' => $this->tokenClaims['capabilities'] ?? null,
        ];
    }
}
