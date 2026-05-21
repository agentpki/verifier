// AgentPKI verifier Worker — Cloudflare Workers entry point.
//
// Routes:
//   GET  /            -> service info
//   GET  /health      -> 200 OK
//   POST /v1/verify   -> verification (see verify.ts)
//   OPTIONS *         -> CORS preflight

import { verifyPassportEdge, type VerifyRequestBody } from './verify.js';
import { cacheStats } from './cache.js';

export interface Env {
  VERIFIER_ID: string;
  SPEC_URL: string;
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '')) {
      return json({
        service: 'agentpki-verifier',
        version: '0.1.0-alpha.1',
        verifier_id: env.VERIFIER_ID,
        spec: env.SPEC_URL,
        endpoints: {
          verify: 'POST /v1/verify',
          health: 'GET /health',
          cache_stats: 'GET /debug/cache',
        },
      });
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true, ts: Math.floor(Date.now() / 1000) });
    }

    if (req.method === 'GET' && url.pathname === '/debug/cache') {
      return json(cacheStats());
    }

    if (req.method === 'POST' && url.pathname === '/v1/verify') {
      return handleVerify(req);
    }

    return json({ error: 'not_found', detail: `${req.method} ${url.pathname}` }, 404);
  },
} satisfies ExportedHandler<Env>;

async function handleVerify(req: Request): Promise<Response> {
  let body: VerifyRequestBody;
  try {
    body = (await req.json()) as VerifyRequestBody;
  } catch (e) {
    return json(
      {
        verified: false,
        verdict: 'deny',
        failure_reason: 'malformed',
        failure_detail: e instanceof Error ? e.message : String(e),
        verifier_id: 'agentpki-verifier-edge',
      },
      400,
    );
  }

  const start = Date.now();
  const result = await verifyPassportEdge(body);
  const elapsed_ms = Date.now() - start;

  // Verification result is itself a 200 OK; the verdict field signals allow/deny.
  // Status 4xx is only for protocol-level errors (bad JSON, missing token).
  return json({ ...result, elapsed_ms });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS,
    },
  });
}
