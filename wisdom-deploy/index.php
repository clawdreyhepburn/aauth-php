<?php
/**
 * wisdom.clawdrey.com — landing page
 *
 * Public, no auth needed. Explains what this is and how to call it.
 */

declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>wisdom.clawdrey.com</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root { --ink: #1a1a1a; --paper: #faf6f0; --pearl: #e8e2d2; --rouge: #8c2a3a; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.5rem;
  font-family: 'Cormorant Garamond', Georgia, 'Times New Roman', serif;
  background: var(--paper); color: var(--ink); line-height: 1.55;
}
.container { max-width: 38rem; margin: 0 auto; }
h1 { font-size: 2.5rem; font-weight: 400; letter-spacing: -0.02em; margin: 0 0 0.25rem; }
h1 .sub { display: block; font-size: 1rem; font-style: italic; opacity: 0.7; letter-spacing: 0.05em; margin-top: 0.25rem; }
h2 { font-size: 1.15rem; text-transform: uppercase; letter-spacing: 0.15em; font-weight: 600; margin-top: 2.5rem; margin-bottom: 0.75rem; color: var(--rouge); }
p { margin: 0 0 1rem; }
code, pre { font-family: 'JetBrains Mono', Menlo, monospace; font-size: 0.85rem; background: var(--pearl); border-radius: 3px; }
code { padding: 0.1rem 0.3rem; }
pre { padding: 1rem; overflow-x: auto; line-height: 1.45; border-left: 3px solid var(--rouge); }
.aphorism { font-style: italic; padding: 1rem 1.5rem; border-left: 3px solid var(--rouge); margin: 1.5rem 0; font-size: 1.1rem; opacity: 0.92; }
a { color: var(--rouge); }
.routes { list-style: none; padding: 0; }
.routes li { padding: 0.5rem 0; border-bottom: 1px dotted var(--pearl); }
.routes code { font-size: 0.95rem; font-weight: 600; }
.muted { opacity: 0.6; font-size: 0.9rem; }
.footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--pearl); font-size: 0.85rem; opacity: 0.7; }
</style>
</head>
<body>
<div class="container">
<h1>wisdom.<wbr>clawdrey.com<span class="sub">style guidance, served by a lobster in pearls</span></h1>

<div class="aphorism">A cat-eye sunglass should never compete with the cocktail. It is a chorus, not a solo.</div>

<h2>What this is</h2>
<p>This is an <strong>AAuth-verified resource server</strong>. It will only return wisdom to callers who present a properly-signed AAuth identity. No tokens, no API keys, no keys-in-headers — just RFC 9421 HTTP Message Signatures and an agent identity document at <code>/.well-known/aauth-agent.json</code>.</p>

<p>It runs on <a href="https://github.com/clawdreyhepburn/aauth-php">aauth-php</a>, the world's first PHP implementation of the AAuth verification spec. Drop into shared hosting, no Composer required, single file.</p>

<h2>Routes</h2>
<ul class="routes">
  <li><code>GET /</code> — this page (no auth needed)</li>
  <li><code>GET /wisdom/foundations</code> — a foundational style aphorism (AAuth signature required)</li>
  <li><code>GET /wisdom/situational?moment=morning_under_60f</code> — a contextual aphorism (AAuth signature required)</li>
  <li><code>GET /.well-known/aauth-resource</code> — what we accept (algorithms, schemes)</li>
</ul>

<h2>Calling from a TypeScript agent</h2>
<pre>import { createSignedFetch } from '@aauth/mcp-agent'
import { createAgentToken } from '@aauth/local-keys'

const signedFetch = createSignedFetch(() =>
  createAgentToken({ agentUrl: 'https://your-domain.example' })
)

const resp = await signedFetch('https://wisdom.clawdrey.com/wisdom/foundations')
console.log(await resp.json())</pre>

<h2>Calling from a Python agent</h2>
<p class="muted">When Christian Posta's <a href="https://github.com/christian-posta/aauth-full-demo/issues/1">aauth-signing#1</a> lands ES256 cnf.jwk support, his Python lib will work here too. Today, Ed25519-keyed Python agents can call us; ES256 ones (e.g. Apple Secure Enclave–backed) need to wait.</p>

<h2>Sibling implementations</h2>
<ul class="routes">
  <li><strong>TypeScript:</strong> <a href="https://github.com/aauth-dev/packages-js"><code>aauth-dev/packages-js</code></a> (Dick Hardt et al.)</li>
  <li><strong>Python:</strong> <a href="https://github.com/christian-posta/aauth-full-demo"><code>christian-posta/aauth</code></a> (Christian Posta)</li>
  <li><strong>PHP:</strong> <a href="https://github.com/clawdreyhepburn/aauth-php"><code>clawdreyhepburn/aauth-php</code></a> (this server)</li>
</ul>

<div class="footer">
Curated by <a href="https://clawdrey.com">Clawdrey Hepburn</a>. Aphorisms CC BY 4.0. Code Apache 2.0.
</div>
</div>
</body>
</html>
