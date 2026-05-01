/**
 * Live integration test: TS @aauth/mcp-agent client → PHP aauth-php server.
 *
 * The mirror of /tmp/posta-interop/interop-ts-to-py.js, but pointed at our
 * own PHP RequestVerifier instead of Posta's Python one. If this passes, our
 * PHP lib has true cross-language interop with the TS reference.
 */

import { createAgentToken } from '/tmp/aauth-hello/local-keys/dist/index.js'
import { createSignedFetch } from '/tmp/aauth-hello/mcp-agent/dist/index.js'

const TARGET = process.env.TARGET || 'http://127.0.0.1:9992/whoami'
const AGENT_URL = 'https://clawdrey.com'

async function main() {
  console.log('=== aauth-php live interop test ===')
  console.log(`agent: ${AGENT_URL}`)
  console.log(`target: ${TARGET}`)
  console.log()

  const getKM = () =>
    createAgentToken({
      agentUrl: AGENT_URL,
      local: 'openclaw',
      tokenLifetime: 600,
    })

  const signedFetch = createSignedFetch(getKM)
  const resp = await signedFetch(TARGET, { method: 'GET' })

  console.log(`<<< HTTP ${resp.status} ${resp.statusText}`)
  const bodyText = await resp.text()
  let body
  try {
    body = JSON.parse(bodyText)
  } catch {
    body = null
  }
  if (body) {
    console.log('Response body:')
    console.log(JSON.stringify(body, null, 2))
  } else {
    console.log('Raw body:', bodyText)
  }

  // Either the test endpoint sets `verified: true` explicitly, or a real
  // wisdom endpoint returns an aphorism alongside the verified agent block.
  // Both are proof that the PHP verifier accepted the request.
  const verified =
    resp.status === 200 &&
    (body?.verified === true ||
      (typeof body?.aphorism === 'string' &&
        typeof body?.agent?.sub === 'string'))

  if (verified) {
    console.log('\n🎯 INTEROP SUCCESS — PHP verified our TS-signed request.')
    process.exit(0)
  } else {
    console.log('\n❌ INTEROP FAILURE.')
    process.exit(1)
  }
}

main().catch((e) => {
  console.error('FATAL:', e)
  process.exit(99)
})
