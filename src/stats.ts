// Public verification stats.
//
// Increments a small set of KV counters on every /v1/verify call so we can
// honestly answer "how many verifications has this verifier handled?" via
// `GET /v1/stats`.
//
// Storage: ABUSE_REPORTS KV (already provisioned, reused to avoid a new
// binding). Keys:
//
//   stats:total                            — every verification, ever (no TTL)
//   stats:total:allow                      — allow verdicts, ever
//   stats:total:deny                       — deny verdicts, ever
//   stats:total:reason:<reason>            — denies by failure_reason
//   stats:daily:<YYYY-MM-DD>               — every verification today
//   stats:daily:<YYYY-MM-DD>:allow         — allow today
//   stats:daily:<YYYY-MM-DD>:deny          — deny today
//   stats:daily:<YYYY-MM-DD>:reason:<R>    — deny+reason today
//
// Trade-offs:
//   - KV is eventually consistent. Get → +1 → Put will lose updates under
//     concurrent bursts. For our scale (sub-1k QPS) this is fine: we'll
//     under-report by a few percent under load.
//   - Daily keys get a 100-day TTL so the keyspace doesn't grow unbounded.
//   - Total keys have NO TTL — they accumulate forever.
//   - We do not store any token, jti, issuer, or sub. Just verdict counts.
//     Privacy-respecting by design.
//
// If accuracy becomes critical later, swap the read-modify-write for a
// Durable Object atomic counter.

export interface StatsBindings {
  ABUSE_REPORTS?: KVNamespace;
}

const KEY_PREFIX = 'stats:';
const DAILY_TTL_SECONDS = 100 * 24 * 60 * 60; // 100 days

function dateKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

async function bump(kv: KVNamespace, key: string, ttlSeconds?: number): Promise<void> {
  try {
    const current = await kv.get(key);
    const next = (Number.parseInt(current ?? '0', 10) || 0) + 1;
    if (ttlSeconds) {
      await kv.put(key, String(next), { expirationTtl: ttlSeconds });
    } else {
      await kv.put(key, String(next));
    }
  } catch {
    // Don't let a stats hiccup break verification. Swallow.
  }
}

/** Increment counters for one verify call. Fire-and-forget; wrap in waitUntil. */
export async function incrementVerifyStats(
  env: StatsBindings,
  result: { verdict: 'allow' | 'deny'; failure_reason?: string },
  at: Date = new Date(),
): Promise<void> {
  if (!env.ABUSE_REPORTS) return; // KV not provisioned — silently skip
  const day = dateKey(at);
  const verdict = result.verdict;

  const tasks: Promise<void>[] = [
    bump(env.ABUSE_REPORTS, `${KEY_PREFIX}total`),
    bump(env.ABUSE_REPORTS, `${KEY_PREFIX}total:${verdict}`),
    bump(env.ABUSE_REPORTS, `${KEY_PREFIX}daily:${day}`, DAILY_TTL_SECONDS),
    bump(env.ABUSE_REPORTS, `${KEY_PREFIX}daily:${day}:${verdict}`, DAILY_TTL_SECONDS),
  ];

  if (verdict === 'deny' && result.failure_reason) {
    const reason = sanitizeReason(result.failure_reason);
    if (reason) {
      tasks.push(bump(env.ABUSE_REPORTS, `${KEY_PREFIX}total:reason:${reason}`));
      tasks.push(bump(env.ABUSE_REPORTS, `${KEY_PREFIX}daily:${day}:reason:${reason}`, DAILY_TTL_SECONDS));
    }
  }

  await Promise.all(tasks);
}

// Allow only the documented failure_reason values to be used as keys
const KNOWN_REASONS = new Set([
  'bad_signature', 'revoked_key', 'expired', 'malformed',
  'replay', 'unknown_kid', 'unknown_issuer', 'abuse_threshold_exceeded',
]);

function sanitizeReason(s: string): string | null {
  if (KNOWN_REASONS.has(s)) return s;
  return null;
}

export interface StatsSnapshot {
  total: number;
  total_by_verdict: { allow: number; deny: number };
  total_by_reason: Record<string, number>;
  last_7_days: Array<{
    date: string;
    total: number;
    allow: number;
    deny: number;
  }>;
  generated_at: number;
  note: string;
}

/** Build a public stats snapshot. ~10 KV reads. */
export async function getStatsSnapshot(env: StatsBindings, now: Date = new Date()): Promise<StatsSnapshot> {
  if (!env.ABUSE_REPORTS) {
    return {
      total: 0,
      total_by_verdict: { allow: 0, deny: 0 },
      total_by_reason: {},
      last_7_days: [],
      generated_at: Math.floor(Date.now() / 1000),
      note: 'KV binding ABUSE_REPORTS not provisioned — stats disabled',
    };
  }

  async function n(key: string): Promise<number> {
    try {
      const v = await env.ABUSE_REPORTS!.get(key);
      return Number.parseInt(v ?? '0', 10) || 0;
    } catch {
      return 0;
    }
  }

  const [total, totalAllow, totalDeny, badSig, revoked, expired, malformed, replay] = await Promise.all([
    n(`${KEY_PREFIX}total`),
    n(`${KEY_PREFIX}total:allow`),
    n(`${KEY_PREFIX}total:deny`),
    n(`${KEY_PREFIX}total:reason:bad_signature`),
    n(`${KEY_PREFIX}total:reason:revoked_key`),
    n(`${KEY_PREFIX}total:reason:expired`),
    n(`${KEY_PREFIX}total:reason:malformed`),
    n(`${KEY_PREFIX}total:reason:replay`),
  ]);

  // Last 7 days (including today). Today first or last? Last (chronological).
  const days: Array<{ date: string; total: number; allow: number; deny: number }> = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const day = dateKey(d);
    const [dTotal, dAllow, dDeny] = await Promise.all([
      n(`${KEY_PREFIX}daily:${day}`),
      n(`${KEY_PREFIX}daily:${day}:allow`),
      n(`${KEY_PREFIX}daily:${day}:deny`),
    ]);
    days.push({ date: day, total: dTotal, allow: dAllow, deny: dDeny });
  }

  return {
    total,
    total_by_verdict: { allow: totalAllow, deny: totalDeny },
    total_by_reason: {
      bad_signature: badSig,
      revoked_key: revoked,
      expired,
      malformed,
      replay,
    },
    last_7_days: days,
    generated_at: Math.floor(Date.now() / 1000),
    note: 'Counters started 2026-06-08. Earlier verifications not counted retroactively.',
  };
}
