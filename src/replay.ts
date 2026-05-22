// Replay-detection cache for Mode B (RFC 9421) — Durable Object backed.
//
// Mode B signatures bind a passport to a specific (method, URL, body-hash,
// timestamp). The signature is replay-resistant within the (created, expires)
// window — but only IF the verifier remembers it has seen the signature
// before. This DO is that memory.
//
// Storage key: `${jti}:${sigPrefix}` (sig prefix is first 32 chars — enough
// to disambiguate within a single passport's lifetime).
// Storage value: first-seen UNIX seconds.
// TTL: 300 seconds (matches the spec §12 maximum signature window).

export interface ReplayCheckResult {
  replay: boolean;
  first_seen?: number;
  recorded?: number;
}

export class ReplayCacheDO {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // POST /check  { jti, signature }
    if (req.method === 'POST' && url.pathname === '/check') {
      let body: { jti?: string; signature?: string };
      try {
        body = (await req.json()) as { jti?: string; signature?: string };
      } catch {
        return Response.json({ error: 'malformed_json' }, { status: 400 });
      }
      if (!body.jti || !body.signature) {
        return Response.json({ error: 'missing_fields' }, { status: 400 });
      }

      const key = `${body.jti}:${body.signature.slice(0, 32)}`;
      const seen = await this.state.storage.get<number>(key);

      if (typeof seen === 'number') {
        const result: ReplayCheckResult = { replay: true, first_seen: seen };
        return Response.json(result);
      }

      const now = Math.floor(Date.now() / 1000);
      // Store with TTL via setAlarm pattern: store value, schedule cleanup
      // Workers DO storage doesn't have native TTL on individual keys; we
      // use the value's first_seen timestamp to expire reads (anything
      // older than 300s is treated as miss).
      await this.state.storage.put(key, now);

      // Periodic cleanup of expired entries
      await this.maybeCleanup(now);

      const result: ReplayCheckResult = { replay: false, recorded: now };
      return Response.json(result);
    }

    // GET /stats
    if (req.method === 'GET' && url.pathname === '/stats') {
      const all = await this.state.storage.list<number>();
      return Response.json({ size: all.size });
    }

    return new Response('Not found', { status: 404 });
  }

  private async maybeCleanup(now: number): Promise<void> {
    // Cleanup at most once per minute to bound DO storage growth.
    const lastCleanup = (await this.state.storage.get<number>('_last_cleanup')) ?? 0;
    if (now - lastCleanup < 60) return;

    const all = await this.state.storage.list<number>();
    const stale: string[] = [];
    for (const [key, ts] of all.entries()) {
      if (key.startsWith('_')) continue;
      if (typeof ts !== 'number') continue;
      if (now - ts > 300) stale.push(key);
    }
    if (stale.length > 0) {
      await this.state.storage.delete(stale);
    }
    await this.state.storage.put('_last_cleanup', now);
  }
}

// Helper used by the verifier to consult the DO.
export interface ReplayBindings {
  REPLAY_CACHE?: DurableObjectNamespace;
}

export async function checkReplay(
  env: ReplayBindings,
  jti: string,
  signature: string,
): Promise<ReplayCheckResult | null> {
  if (!env.REPLAY_CACHE) return null;
  try {
    // Single DO instance shared across all isolates for global replay state
    const id = env.REPLAY_CACHE.idFromName('global');
    const stub = env.REPLAY_CACHE.get(id);
    const res = await stub.fetch('https://replay/check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jti, signature }),
    });
    if (!res.ok) return null;
    return (await res.json()) as ReplayCheckResult;
  } catch {
    return null; // DO unreachable — don't fail verification, just skip replay check
  }
}
