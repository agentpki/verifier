// Public read-only endpoints that the AgentPKI extension (and any other
// downstream client) uses to render:
//   - the curated list of trusted issuers (for the popup verified-issuer
//     resolver + UI badges)
//   - per-passport reputation summaries (abuse-report counts, revocation,
//     simple reputation score)
//
// Both are deliberately public + cacheable. No auth, no per-client gating.
// v0.1 seeds trusted-issuers from a hardcoded list; v0.2 will read from KV
// so adding/removing an issuer doesn't require a deploy.

const TRUSTED_ISSUERS_V1 = [
  {
    issuer: 'demo.agentpki.dev',
    name: 'AgentPKI Demo Issuer',
    tier: 1,
    note: 'Demo issuer for agentpki.dev/demo. Public, unauthenticated /mint — DO NOT use in production.',
    added_at: 1716249600, // 2024-05-20
  },
  {
    issuer: 'agentpki.dev',
    name: 'AgentPKI Self-Issuer',
    tier: 2,
    note: 'Self-issued identity for the AgentPKI project itself. Operated by Sarvesh Patel.',
    added_at: 1716249600,
  },
] as const;

export interface TrustedIssuer {
  issuer: string;
  name: string;
  tier: number;
  note?: string;
  added_at: number;
}

export function buildTrustedIssuers(): { v: 1; updated_at: number; issuers: TrustedIssuer[] } {
  return {
    v: 1,
    updated_at: Math.floor(Date.now() / 1000),
    issuers: TRUSTED_ISSUERS_V1 as unknown as TrustedIssuer[],
  };
}

// ─── Per-passport reputation summary ──────────────────────────────────
//
// Returns a coarse-grained summary the extension uses to color its badge
// when there's no real-time verify call:
//   - abuse_reports_count: count of stored abuse reports against this passport
//   - last_report_at:      unix timestamp of most recent report (or null)
//   - revoked:             whether the passport's jti is in any issuer's CRL
//                          (extension passes the jti; we can't infer issuer)
//   - reputation_score:    0.0 (clean) → 1.0 (high-confidence bad), simple
//                          formula based on report count + severity
//
// All KV lookups are best-effort. If ABUSE_REPORTS isn't bound (local dev
// or fresh deploy), we return a neutral response with `data_available: false`.

export interface ReputationSummary {
  v: 1;
  passport_id: string;
  abuse_reports_count: number;
  last_report_at: number | null;
  reputation_score: number; // 0.0 to 1.0
  data_available: boolean;
  generated_at: number;
}

export interface ReputationBindings {
  ABUSE_REPORTS?: KVNamespace;
}

export async function buildReputationSummary(
  passportId: string,
  env: ReputationBindings,
): Promise<ReputationSummary> {
  const now = Math.floor(Date.now() / 1000);
  const base: ReputationSummary = {
    v: 1,
    passport_id: passportId,
    abuse_reports_count: 0,
    last_report_at: null,
    reputation_score: 0.0,
    data_available: false,
    generated_at: now,
  };

  if (!env.ABUSE_REPORTS) {
    return base;
  }

  // Reports are indexed under `jti:<passport_id>` per-jti, value is a JSON
  // array of report_ids. The full report bodies live under `report:<id>`.
  let reportIds: string[] = [];
  try {
    const raw = await env.ABUSE_REPORTS.get(`jti:${passportId}`, 'json');
    if (Array.isArray(raw)) reportIds = raw as string[];
  } catch {
    // Treat KV errors as "no data" rather than failing the request
    return base;
  }

  if (reportIds.length === 0) {
    return { ...base, data_available: true };
  }

  // Fetch up to 50 reports for severity-weighting (cap to limit KV reads)
  const sampleIds = reportIds.slice(-50);
  let weightedSum = 0;
  let lastTs: number | null = null;

  for (const id of sampleIds) {
    try {
      const r = await env.ABUSE_REPORTS.get(`report:${id}`, 'json');
      if (!r || typeof r !== 'object') continue;
      const report = r as { severity?: string; received_at?: number };
      const w = SEVERITY_WEIGHT[report.severity ?? 'medium'] ?? 0.3;
      weightedSum += w;
      if (report.received_at && (lastTs === null || report.received_at > lastTs)) {
        lastTs = report.received_at;
      }
    } catch {
      // Skip unreadable report
    }
  }

  // Squash to [0, 1] with a simple saturating curve: 5 medium-weight reports
  // → ~0.6, 15 → ~0.85, 30+ → ~1.0
  const score = Math.min(1, 1 - Math.exp(-weightedSum / 6));

  return {
    v: 1,
    passport_id: passportId,
    abuse_reports_count: reportIds.length,
    last_report_at: lastTs,
    reputation_score: Math.round(score * 100) / 100,
    data_available: true,
    generated_at: now,
  };
}

const SEVERITY_WEIGHT: Record<string, number> = {
  low: 0.1,
  medium: 0.3,
  high: 0.6,
  critical: 1.0,
};
