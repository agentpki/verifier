// Abuse report submission endpoint per spec §11.
//
// Any relying site OR an issuer can POST an abuse report tied to a passport
// jti or agent_id. Reports are stored with 90-day retention for human review
// and feed the future abuse_score aggregation pipeline.
//
// v0.2 implements:
//   - report ingest (POST /v1/abuse/report)
//   - basic schema validation
//   - 14-day KV retention
//   - per-jti and per-agent_id index for aggregator
//
// v0.3 will add:
//   - real abuse_score aggregation (currently hardcoded 0.0 in verify.ts)
//   - per-issuer rate limits for reporters
//   - downstream notification (webhook to issuer's abuse_report_url)

import { util } from '@agentpki/sdk';
import { SEVERITY_WEIGHT } from './severity.js';

export interface AbuseReport {
  v: 1;
  reporter: string;        // domain of the reporting site, OR a UUID/installation-id
                           // when reporter_kind === 'extension'
  reporter_kind?: 'site' | 'extension' | 'issuer' | 'web';
                           // v0.1 default = 'site' (preserves backward-compat with
                           // pre-extension submissions). Extension and web reports
                           // send their own kind so we can route through a
                           // different rate limiter and tier the trust signal
                           // lower than a known site's reports. 'web' = a report
                           // filed from the public agentpki.dev/check verifier UI.
  passport_jti?: string;
  agent_id?: string;
  category:
    | 'rate-abuse'
    | 'malicious-payload'
    | 'policy-violation'
    | 'spam'
    | 'scraping-overrun'
    | 'impersonation'   // v0.1 (extension) — agent claims an issuer it can't prove
    | 'fraud'           // v0.1 (extension) — payment / harm / phishing
    | 'harm'            // v0.1 (extension) — user-reported "this agent did damage"
    | 'scope-violation' // v0.1 (extension) — agent acted outside its declared scope
    | 'other';
  severity: 'low' | 'medium' | 'high' | 'critical';
  occurred_at: number;
  description: string;
  evidence_urls?: string[];
  requested_action?: 'warn' | 'throttle' | 'revoke';
}

export interface StoredAbuseReport extends AbuseReport {
  report_id: string;
  received_at: number;
}

export interface AbuseBindings {
  ABUSE_REPORTS?: KVNamespace;
}

const REPORT_RETENTION_SECONDS = 14 * 86400; // 14 days

export async function handleAbuseReport(
  req: Request,
  env: AbuseBindings,
): Promise<Response> {
  let body: AbuseReport;
  try {
    body = (await req.json()) as AbuseReport;
  } catch (e) {
    return json(
      { error: 'malformed_json', detail: e instanceof Error ? e.message : String(e) },
      400,
    );
  }

  const validation = validateReport(body);
  if (!validation.ok) {
    return json({ error: 'invalid_report', detail: validation.error }, 400);
  }

  const reportId = `r_${util.randomHex(12)}`;
  const stored: StoredAbuseReport = {
    ...body,
    report_id: reportId,
    received_at: Math.floor(Date.now() / 1000),
  };

  // Persist to KV. We write THREE classes of keys per report:
  //
  //   1. `report:<id>`           - full report body (for review tooling)
  //   2. `by-jti:<jti>:<id>`     - pointer index, enumerable via KV.list
  //   3. `by-agent:<aid>:<id>`   - pointer index by agent_id
  //
  // AND we read-modify-write a per-jti summary scalar:
  //
  //   4. `summary:by-jti:<jti>`  - { count, weighted_sum, last_ts }
  //
  // The summary lets directory.ts compute reputation via a single KV.get,
  // which is fast-consistent (sub-second). KV.list has up to 60s eventual
  // consistency for newly-written keys, which would make the popup show
  // stale Clean / 0 reports for up to a minute after a report submit.
  if (env.ABUSE_REPORTS) {
    const opts = { expirationTtl: REPORT_RETENTION_SECONDS };
    const writes: Promise<void>[] = [
      env.ABUSE_REPORTS.put(`report:${reportId}`, JSON.stringify(stored), opts),
    ];
    if (body.passport_jti) {
      writes.push(
        env.ABUSE_REPORTS.put(
          `by-jti:${body.passport_jti}:${reportId}`,
          reportId,
          opts,
        ),
      );
    }
    if (body.agent_id) {
      writes.push(
        env.ABUSE_REPORTS.put(
          `by-agent:${body.agent_id}:${reportId}`,
          reportId,
          opts,
        ),
      );
    }
    try {
      await Promise.all(writes);
    } catch {
      // KV failure shouldn't block a 202 — we already validated; tell reporter
      // we'll review even if we lost durability here. Log for retry pipeline.
      return json({ accepted: true, report_id: reportId, durable: false }, 202);
    }

    // Maintain the per-jti summary counter for fast reputation reads.
    // Best-effort read-modify-write: a tiny race window can undercount by 1
    // on simultaneous submissions, which is acceptable for an abuse signal.
    // The intentional ordering — pointer writes BEFORE summary write — means
    // a summary failure leaves the durable trail intact for offline rollup.
    if (body.passport_jti) {
      try {
        await bumpSummary(env.ABUSE_REPORTS, body.passport_jti, body.severity, stored.received_at);
      } catch {
        // Summary is a denormalization, not the source of truth — swallow.
      }
    }
  }

  return json({ accepted: true, report_id: reportId, durable: !!env.ABUSE_REPORTS }, 202);
}

interface ValidationOk { ok: true }
interface ValidationErr { ok: false; error: string }

function validateReport(r: AbuseReport): ValidationOk | ValidationErr {
  if (r.v !== 1) return { ok: false, error: 'unsupported version' };
  if (typeof r.reporter !== 'string' || r.reporter.length < 3) {
    return { ok: false, error: 'reporter must be a string (domain or installation-id)' };
  }
  // v0.1: reporter_kind is optional with default 'site' for backward-compat.
  // Future deploys can flip the default once all callers send it explicitly.
  if (r.reporter_kind !== undefined) {
    const validKinds = ['site', 'extension', 'issuer', 'web'];
    if (!validKinds.includes(r.reporter_kind)) {
      return { ok: false, error: `reporter_kind must be one of: ${validKinds.join(', ')}` };
    }
    // Extension and web reporters must look like a UUID (validated cheaply:
    // 36 chars, four dashes, hex). Not bulletproof — just rejects obvious
    // garbage. Issuer/site reporters use domain identifiers and don't get this
    // validation.
    if (r.reporter_kind === 'extension' || r.reporter_kind === 'web') {
      const uuidish = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidish.test(r.reporter)) {
        return { ok: false, error: `${r.reporter_kind} reporter must be a UUID` };
      }
    }
  }
  if (!r.passport_jti && !r.agent_id) {
    return { ok: false, error: 'at least one of passport_jti or agent_id required' };
  }
  const validCats = [
    'rate-abuse', 'malicious-payload', 'policy-violation',
    'spam', 'scraping-overrun', 'impersonation', 'fraud',
    'harm', 'scope-violation', 'other',
  ];
  if (!validCats.includes(r.category)) {
    return { ok: false, error: `category must be one of: ${validCats.join(', ')}` };
  }
  const validSev = ['low', 'medium', 'high', 'critical'];
  if (!validSev.includes(r.severity)) {
    return { ok: false, error: `severity must be one of: ${validSev.join(', ')}` };
  }
  if (typeof r.occurred_at !== 'number') {
    return { ok: false, error: 'occurred_at must be a UNIX seconds integer' };
  }
  if (typeof r.description !== 'string' || r.description.length < 4) {
    return { ok: false, error: 'description must be at least 4 chars' };
  }
  if (r.evidence_urls && !Array.isArray(r.evidence_urls)) {
    return { ok: false, error: 'evidence_urls must be array of strings' };
  }
  return { ok: true };
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

/** Summary record persisted at `summary:by-jti:<jti>`. Updated on each report. */
export interface JtiReputationSummary {
  count: number;
  weighted_sum: number;
  last_ts: number;
}

async function bumpSummary(
  kv: KVNamespace,
  jti: string,
  severity: AbuseReport['severity'],
  receivedAt: number,
): Promise<void> {
  const key = `summary:by-jti:${jti}`;
  const raw = (await kv.get(key, 'json')) as JtiReputationSummary | null;
  const w = SEVERITY_WEIGHT[severity] ?? 0.3;
  const next: JtiReputationSummary = {
    count: (raw?.count ?? 0) + 1,
    weighted_sum: (raw?.weighted_sum ?? 0) + w,
    last_ts: Math.max(raw?.last_ts ?? 0, receivedAt),
  };
  await kv.put(key, JSON.stringify(next), {
    expirationTtl: REPORT_RETENTION_SECONDS,
  });
}
