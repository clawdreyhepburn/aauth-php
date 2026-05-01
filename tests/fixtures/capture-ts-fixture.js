/**
 * Fixture capture: produce signed requests with our TS @aauth/mcp-agent and
 * dump everything (request line, headers, body, signature base inputs) as
 * JSON. Used as ground truth for the PHP implementation's signature-base
 * builder.
 */

import { createAgentToken } from '/tmp/aauth-hello/local-keys/dist/index.js'
import { createSignedFetch } from '/tmp/aauth-hello/mcp-agent/dist/index.js'
import http from 'node:http'
import { writeFileSync } from 'node:fs'

const PORT = 19999
const FIXTURES_PATH = process.argv[2] || '/Users/clawdreyhepburn/aauth-php/tests/fixtures/ts-signed.json'

// Stand up a tiny HTTP server that captures incoming signed requests.
const captures = []
const server = http.createServer((req, res) => {
  let body = []
  req.on('data', (chunk) => body.push(chunk))
  req.on('end', () => {
    const bodyBuf = Buffer.concat(body)
    captures.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body_b64: bodyBuf.toString('base64'),
      body_text: bodyBuf.toString('utf8'),
    })
    res.statusCode = 200
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({ ok: true }))
  })
})

server.listen(PORT, '127.0.0.1', async () => {
  const km = await createAgentToken({
    agentUrl: 'https://clawdrey.com',
    local: 'openclaw',
    tokenLifetime: 600,
  })

  const signedFetch = createSignedFetch(() => Promise.resolve(km))

  // Capture multiple shapes: GET no body, GET with query, POST with JSON body.
  const calls = [
    { url: `http://127.0.0.1:${PORT}/whoami`, init: { method: 'GET' } },
    { url: `http://127.0.0.1:${PORT}/things?id=42&kind=lobster`, init: { method: 'GET' } },
    {
      url: `http://127.0.0.1:${PORT}/things`,
      init: {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'pearl', count: 7 }),
      },
    },
  ]

  for (const call of calls) {
    try {
      const r = await signedFetch(call.url, call.init)
      await r.text()
    } catch (e) {
      console.error('signedFetch error:', e.message)
    }
  }

  // Fetch the live JWKS at the time of capture so we always have the
  // current published key (the local-keys backend may rotate between captures).
  const jwksResp = await fetch('https://clawdrey.com/.well-known/jwks.json')
  const jwks = await jwksResp.json()
  const kid = km.signatureKey.type === 'jwt'
    ? JSON.parse(Buffer.from(km.signatureKey.jwt.split('.')[0], 'base64url').toString()).kid
    : null
  const expectedJwk = jwks.keys.find((k) => k.kid === kid) || jwks.keys[0]

  writeFileSync(
    FIXTURES_PATH,
    JSON.stringify(
      {
        captured_at: new Date().toISOString(),
        agent: 'aauth:openclaw@clawdrey.com',
        agent_url: 'https://clawdrey.com',
        kid,
        expected_jwk: expectedJwk,
        captures,
      },
      null,
      2
    )
  )

  console.log(`wrote ${captures.length} fixtures to ${FIXTURES_PATH}`)
  server.close()
  process.exit(0)
})
