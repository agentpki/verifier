// AgentPKI verifier Worker — Cloudflare Workers entry point.
//
// Routes (v0.2):
//   GET  /                    -> service info
//   GET  /health              -> liveness probe
//   GET  /debug/cache         -> in-memory cache stats
//   POST /v1/verify           -> verification (spec §8)
//   POST /v1/abuse/report     -> abuse report submission (spec §11)  [v0.2]
//   OPTIONS *                 -> CORS preflight
//
// Optional bindings (env):
//   ISSUER_CACHE     KV — cross-isolate issuer directory cache
//   CRL_CACHE        KV — cross-isolate CRL cache (per spec §10)
//   ABUSE_REPORTS    KV — abuse-report storage (14-day retention)
//   REPLAY_CACHE     Durable Object namespace — Mode B replay detection
//
// All bindings are OPTIONAL. The verifier falls back gracefully if any
// binding is absent: in-memory caches still serve, CRL checks are skipped
// (treated as "unknown revocation state"), replay detection is skipped.
// This means the v0.2 code can be deployed BEFORE the user provisions the
// KV/DO bindings — no breakage.

import { verifyPassportEdge, type VerifyRequestBody, type VerifierBindings } from './verify.js';
import { cacheStats } from './cache.js';
import { handleAbuseReport, type AbuseBindings } from './abuse.js';

// Re-export the DO class for Cloudflare's runtime to discover it
export { ReplayCacheDO } from './replay.js';

export interface Env extends VerifierBindings, AbuseBindings {
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
        version: '0.2.0-alpha.1',
        verifier_id: env.VERIFIER_ID,
        spec: env.SPEC_URL,
        endpoints: {
          verify: 'POST /v1/verify',
          abuse_report: 'POST /v1/abuse/report',
          health: 'GET /health',
          cache_stats: 'GET /debug/cache',
        },
        bindings: {
          issuer_cache: env.ISSUER_CACHE ? 'kv' : 'memory-only',
          crl_cache: env.CRL_CACHE ? 'kv' : 'origin-fetch-only',
          abuse_reports: env.ABUSE_REPORTS ? 'kv' : 'not-stored',
          replay_cache: env.REPLAY_CACHE ? 'durable-object' : 'disabled',
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
      return handleVerify(req, env);
    }

    if (req.method === 'POST' && url.pathname === '/v1/abuse/report') {
      return withCors(await handleAbuseReport(req, env));
    }

    return json({ error: 'not_found', detail: `${req.method} ${url.pathname}` }, 404);
  },
} satisfies ExportedHandler<Env>;

async function handleVerify(req: Request, env: Env): Promise<Response> {
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
  const result = await verifyPassportEdge(body, env);
  const elapsed_ms = Date.now() - start;

  return json({ ...result, elapsed_ms });
}

function withCors(res: Response): Response {
  const newHeaders = new Headers(res.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) newHeaders.set(k, v);
  return new Response(res.body, { status: res.status, headers: newHeaders });
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
