// Shareable verification result storage.
//
// Powers `agentpki.dev/check/result/<id>` — a permanent URL anyone can share
// that renders the exact verification result the original user saw.
//
// Storage shape:
//   verify-snap:<id>  →  JSON snapshot of the result
//
// Snapshot lives in the same ABUSE_REPORTS KV namespace under a distinct
// prefix so we don't need to provision a new binding. TTL is bounded by the
// verifier's `cached_until` field (or a 24h cap, whichever is shorter) since
// nobody wants to share a verification result that's already stale.
//
// IDs are short, URL-safe base32 (12 chars = ~60 bits). Collisions at this
// length are practically impossible at our scale.

import { util } from '@agentpki/sdk';

export interface VerificationStoreBindings {
  ABUSE_REPORTS?: KVNamespace;
}

const STORE_PREFIX = 'verify-snap:';
const MAX_TTL_SECONDS = 24 * 60 * 60;  // 24 hours — beyond this, verify fresh
const MIN_TTL_SECONDS = 60;             // floor — Cloudflare KV minimum

export async function storeVerification(
  req: Request,
  env: VerificationStoreBindings,
): Promise<Response> {
  if (!env.ABUSE_REPORTS) {
    return json(
      { error: 'storage_not_configured', detail: 'KV binding ABUSE_REPORTS is not set' },
      503,
    );
  }

  let body: { result?: unknown; input?: string; ttl_seconds?: number };
  try {
    body = (await req.json()) as typeof body;
  } catch (e) {
    return json(
      { error: 'malformed_json', detail: e instanceof Error ? e.message : String(e) },
      400,
    );
  }

  if (!body.result || typeof body.result !== 'object') {
    return json({ error: 'missing_result', detail: 'result field is required and must be an object' }, 400);
  }

  // Bound the TTL: client requests a TTL, we clamp to [60s, 24h]
  let ttl = MAX_TTL_SECONDS;
  if (typeof body.ttl_seconds === 'number') {
    ttl = Math.max(MIN_TTL_SECONDS, Math.min(MAX_TTL_SECONDS, Math.floor(body.ttl_seconds)));
  }

  // 12 hex chars = 48 bits. Collision-free at any practical share volume.
  const id = util.randomHex(6);
  const snap = {
    v: 1,
    id,
    stored_at: Math.floor(Date.now() / 1000),
    input: typeof body.input === 'string' ? body.input.slice(0, 1024) : null,
    result: body.result,
  };

  try {
    await env.ABUSE_REPORTS.put(STORE_PREFIX + id, JSON.stringify(snap), {
      expirationTtl: ttl,
    });
  } catch (e) {
    return json(
      { error: 'storage_write_failed', detail: e instanceof Error ? e.message : String(e) },
      500,
    );
  }

  return json({ id, ttl_seconds: ttl, expires_at: snap.stored_at + ttl }, 200, {
    'Cache-Control': 'no-store',
  });
}

export async function fetchVerification(
  id: string,
  env: VerificationStoreBindings,
): Promise<Response> {
  if (!/^[0-9a-f]{8,16}$/i.test(id)) {
    return json({ error: 'invalid_id' }, 400);
  }

  if (!env.ABUSE_REPORTS) {
    return json({ error: 'storage_not_configured' }, 503);
  }

  let snap;
  try {
    snap = await env.ABUSE_REPORTS.get(STORE_PREFIX + id, 'json');
  } catch {
    return json({ error: 'storage_read_failed' }, 500);
  }

  if (!snap) {
    return json(
      { error: 'not_found', detail: 'No verification with that ID. It may have expired (24h TTL) or never existed.' },
      404,
    );
  }

  // 5-min Cache-Control so popular shared results stay snappy
  return json(snap, 200, { 'Cache-Control': 'public, max-age=300, stale-while-revalidate=900' });
}

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extra },
  });
}
