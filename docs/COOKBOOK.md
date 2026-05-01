# aauth-php cookbook

Practical recipes for getting `aauth-php` running in a real PHP application.
Each recipe is self-contained and pasteable.

- [Recipe 1: Verify a single endpoint](#recipe-1-verify-a-single-endpoint)
- [Recipe 2: Reusable middleware function](#recipe-2-reusable-middleware-function)
- [Recipe 3: Optional auth (allow signed and unsigned)](#recipe-3-optional-auth-allow-signed-and-unsigned)
- [Recipe 4: Allowlist of agent identities](#recipe-4-allowlist-of-agent-identities)
- [Recipe 5: WordPress shortcode that returns aphorisms only to verified agents](#recipe-5-wordpress-shortcode-that-returns-aphorisms-only-to-verified-agents)
- [Recipe 6: Slim 4 / Laravel](#recipe-6-slim-4--laravel)
- [Recipe 7: Local development without HTTPS](#recipe-7-local-development-without-https)
- [Recipe 8: Custom JWKS cache directory](#recipe-8-custom-jwks-cache-directory)
- [Recipe 9: Surfacing failure detail to logs without leaking it to callers](#recipe-9-surfacing-failure-detail-to-logs-without-leaking-it-to-callers)
- [Recipe 10: Smoke-test your endpoint with the TS reference client](#recipe-10-smoke-test-your-endpoint-with-the-ts-reference-client)

---

## Recipe 1: Verify a single endpoint

The minimum viable AAuth gateway. Drop this at the top of any handler:

```php
<?php
require_once __DIR__ . '/aauth-bundle.php';

use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

$verifier = new RequestVerifier([
    'canonical_authorities' => ['example.com'],
]);

try {
    $result = $verifier->verifyRequest([
        'method'  => $_SERVER['REQUEST_METHOD'],
        'uri'     => 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
        'headers' => getallheaders(),
        'body'    => file_get_contents('php://input'),
    ]);
} catch (AAuthException $e) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'aauth_verification_failed']);
    exit;
}

// Verified. Continue.
header('Content-Type: application/json');
echo json_encode([
    'hello' => $result->agentSub,
]);
```

---

## Recipe 2: Reusable middleware function

Lift it into a helper so multiple endpoints can share it:

```php
<?php
function require_aauth(): \Clawdrey\AAuth\VerifyResult
{
    static $verifier = null;
    if ($verifier === null) {
        $verifier = new \Clawdrey\AAuth\RequestVerifier([
            'canonical_authorities' => ['example.com', 'api.example.com'],
        ]);
    }

    try {
        return $verifier->verifyRequest([
            'method'  => $_SERVER['REQUEST_METHOD'],
            'uri'     => 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
            'headers' => getallheaders(),
            'body'    => file_get_contents('php://input'),
        ]);
    } catch (\Clawdrey\AAuth\AAuthException $e) {
        error_log('aauth verify failed: ' . $e->getMessage());
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'aauth_verification_failed']);
        exit;
    }
}
```

Then in any endpoint:

```php
<?php
require_once __DIR__ . '/aauth-bundle.php';
require_once __DIR__ . '/lib/require-aauth.php';

$caller = require_aauth();   // VerifyResult or never returns

// ...your business logic...
```

---

## Recipe 3: Optional auth (allow signed and unsigned)

For endpoints where AAuth grants extra capabilities but you don't want to
hard-block unsigned callers (e.g., a public landing page that sometimes
returns enriched content for verified agents):

```php
<?php
function try_aauth(): ?\Clawdrey\AAuth\VerifyResult
{
    if (!isset($_SERVER['HTTP_SIGNATURE_KEY'])) {
        return null;  // not even attempted
    }

    try {
        $verifier = new \Clawdrey\AAuth\RequestVerifier([
            'canonical_authorities' => ['example.com'],
        ]);
        return $verifier->verifyRequest([
            'method'  => $_SERVER['REQUEST_METHOD'],
            'uri'     => 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'],
            'headers' => getallheaders(),
            'body'    => file_get_contents('php://input'),
        ]);
    } catch (\Clawdrey\AAuth\AAuthException) {
        return null;  // attempted but invalid: treat as anonymous
    }
}

$caller = try_aauth();

if ($caller !== null) {
    echo "hello, {$caller->agentSub}";
} else {
    echo "hello, stranger";
}
```

> ⚠️ Be deliberate about this pattern. If your endpoint relies on the
> *attempted-but-failed* signal for anything (rate-limiting, abuse logging,
> etc.), do that **before** the `return null` so a malformed request can't
> just silently downgrade to anonymous.

---

## Recipe 4: Allowlist of agent identities

Once verification passes, you still need to decide whether *this particular
agent* is allowed to do the thing they asked for. The verifier only tells
you the request is authentic; authorization is your call.

```php
<?php
$caller = require_aauth();

$ALLOWLIST = [
    'aauth:openclaw@clawdrey.com',
    'aauth:reviewer@aauth.dev',
];

if (!in_array($caller->agentSub, $ALLOWLIST, true)) {
    http_response_code(403);
    echo json_encode(['error' => 'agent_not_allowed', 'sub' => $caller->agentSub]);
    exit;
}

// proceed
```

For richer policy, use the `tokenClaims` array on `VerifyResult` — it
contains the full decoded JWT payload, including any `capabilities` /
`scope` / custom claims your issuer puts there.

---

## Recipe 5: WordPress shortcode that returns aphorisms only to verified agents

Drop the bundle into your theme directory and register a shortcode:

```php
<?php
// wp-content/themes/your-theme/aauth-shortcode.php
require_once __DIR__ . '/aauth-bundle.php';

add_shortcode('aauth_wisdom', function () {
    try {
        $verifier = new \Clawdrey\AAuth\RequestVerifier([
            'canonical_authorities' => [parse_url(home_url(), PHP_URL_HOST)],
        ]);
        $result = $verifier->verifyRequest([
            'method'  => $_SERVER['REQUEST_METHOD'],
            'uri'     => home_url($_SERVER['REQUEST_URI']),
            'headers' => function_exists('getallheaders') ? getallheaders() : [],
            'body'    => file_get_contents('php://input'),
        ]);
    } catch (\Clawdrey\AAuth\AAuthException) {
        return '<em>Sign your request to receive wisdom.</em>';
    }

    return sprintf(
        '<blockquote>Hello, %s. %s</blockquote>',
        esc_html($result->agentSub),
        esc_html(wp_get_random_aphorism())   // your function
    );
});
```

Register from your theme's `functions.php` with
`require_once __DIR__ . '/aauth-shortcode.php';`.

---

## Recipe 6: Slim 4 / Laravel

### Slim 4 PSR-15 middleware

```php
<?php
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as Handler;
use Slim\Psr7\Response;
use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

final class AAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RequestVerifier $verifier,
    ) {}

    public function process(Request $request, Handler $handler): \Psr\Http\Message\ResponseInterface
    {
        try {
            $uri = (string)$request->getUri();
            $headers = [];
            foreach ($request->getHeaders() as $k => $v) {
                $headers[$k] = is_array($v) ? implode(', ', $v) : $v;
            }
            $result = $this->verifier->verifyRequest([
                'method'  => $request->getMethod(),
                'uri'     => $uri,
                'headers' => $headers,
                'body'    => (string)$request->getBody(),
            ]);
            $request = $request->withAttribute('aauth', $result);
        } catch (AAuthException $e) {
            $r = new Response();
            $r->getBody()->write(json_encode(['error' => 'aauth_verification_failed']));
            return $r->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        return $handler->handle($request);
    }
}
```

In your handler: `$caller = $request->getAttribute('aauth');`

### Laravel middleware

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\AAuthException;

class RequireAAuth
{
    public function __construct(private RequestVerifier $verifier) {}

    public function handle(Request $request, Closure $next)
    {
        try {
            $result = $this->verifier->verifyRequest([
                'method'  => $request->method(),
                'uri'     => $request->fullUrl(),
                'headers' => collect($request->headers->all())
                    ->map(fn ($v) => is_array($v) ? implode(', ', $v) : $v)
                    ->all(),
                'body'    => $request->getContent(),
            ]);
            $request->attributes->set('aauth', $result);
        } catch (AAuthException $e) {
            return response()->json(['error' => 'aauth_verification_failed'], 401);
        }

        return $next($request);
    }
}
```

Bind in a `ServiceProvider`:

```php
$this->app->singleton(RequestVerifier::class, fn () => new RequestVerifier([
    'canonical_authorities' => [config('app.aauth_authority')],
]));
```

---

## Recipe 7: Local development without HTTPS

By default `JwksFetcher` refuses non-HTTPS JWKS endpoints. If you're testing
against a local agent that publishes its JWKS at `http://127.0.0.1:9990`,
opt back into `http://`:

```php
<?php
use Clawdrey\AAuth\RequestVerifier;
use Clawdrey\AAuth\JwksFetcher;

$verifier = new RequestVerifier([
    'canonical_authorities' => ['localhost', '127.0.0.1:8080'],
    'jwks_fetcher' => new JwksFetcher([
        'allow_insecure_scheme' => true,   // dev only!
        'verify_tls'            => false,  // self-signed certs
    ]),
]);
```

> 🚨 **Never** set `allow_insecure_scheme` in production. `file://`,
> `ftp://`, and other dangerous schemes remain blocked even with this
> opt-in, but `http://` is plenty bad on its own (MITM, downgrade, etc.).

---

## Recipe 8: Custom JWKS cache directory

The default cache lives in `sys_get_temp_dir() . '/aauth-jwks-cache'`. On
some shared hosts you may want it under your application's writable
directory instead, both for predictability and to keep it private to your
user account:

```php
<?php
use Clawdrey\AAuth\JwksFetcher;
use Clawdrey\AAuth\RequestVerifier;

$verifier = new RequestVerifier([
    'canonical_authorities' => ['api.example.com'],
    'jwks_fetcher' => new JwksFetcher([
        'cache_dir'   => __DIR__ . '/cache/aauth-jwks',
        'ttl_seconds' => 3600,
    ]),
]);
```

Make sure the directory is created with mode `0700` and writable only by
the PHP user. If you point it at a shared location like `/tmp` on a
multi-tenant host, an attacker on the same host can substitute keys.

---

## Recipe 9: Surfacing failure detail to logs without leaking it to callers

`AAuthException` messages are intentionally informative: "JWT expired", "no
key with kid=...", "signature base mismatch". Useful in logs, dangerous in
responses (they tell an attacker exactly what to fix).

```php
<?php
try {
    $result = $verifier->verifyRequest($req);   // $req built as in earlier recipes
} catch (\Clawdrey\AAuth\AAuthException $e) {
    error_log(sprintf(
        '[aauth] %s from %s: %s',
        get_class($e),
        $_SERVER['REMOTE_ADDR'] ?? '?',
        $e->getMessage()
    ));

    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'aauth_verification_failed',
        // do NOT include $e->getMessage() here
    ]);
    exit;
}
```

Catch the specific subclasses if you want different handling for different
failure modes:

```php
catch (\Clawdrey\AAuth\TokenLifetimeException $e) {
    // expired/replayed: maybe rate-limit the source
}
catch (\Clawdrey\AAuth\InvalidSignatureException $e) {
    // bad crypto: log loudly, this is unusual
}
catch (\Clawdrey\AAuth\KeyResolutionException $e) {
    // upstream JWKS unreachable: maybe surface as 502, not 401
    http_response_code(502);
    exit;
}
```

---

## Recipe 10: Smoke-test your endpoint with the TS reference client

Once your endpoint is up, point the AAuth TypeScript reference client at
it. The `tests/interop-live.js` in this repo is the template:

```js
import { createAgentToken } from '@aauth/local-keys'
import { createSignedFetch } from '@aauth/mcp-agent'

const TARGET = process.env.TARGET || 'https://your-domain.example/protected'

const getKM = () => createAgentToken({
    agentUrl: 'https://your-agent.example',
    local: 'your-local-name',
    tokenLifetime: 600,
})

const signedFetch = createSignedFetch(getKM)
const resp = await signedFetch(TARGET, { method: 'GET' })

console.log(resp.status)
console.log(await resp.text())
```

The agent's well-known JWKS at `https://your-agent.example/.well-known/jwks.json`
must be reachable from your PHP host. Once it is, `signedFetch` produces a
real signed request that your `RequestVerifier` will accept.
