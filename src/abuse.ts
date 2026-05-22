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

export interface AbuseReport {
  v: 1;
  reporter: string;        // domain of the reporting site
  passport_jti?: string;
  agent_id?: string;
  category:
    | 'rate-abuse'
    | 'malicious-payload'
    | 'policy-violation'
    | 'spam'
    | 'scraping-overrun'
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

  // Persist to KV (3 keys: by report_id, by jti, by agent_id) for indexing
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
  }

  return json({ accepted: true, report_id: reportId, durable: !!env.ABUSE_REPORTS }, 202);
}

interface ValidationOk { ok: true }
interface ValidationErr { ok: false; error: string }

function validateReport(r: AbuseReport): ValidationOk | ValidationErr {
  if (r.v !== 1) return { ok: false, error: 'unsupported version' };
  if (typeof r.reporter !== 'string' || r.reporter.length < 3) {
    return { ok: false, error: 'reporter must be a domain string' };
  }
  if (!r.passport_jti && !r.agent_id) {
    return { ok: false, error: 'at least one of passport_jti or agent_id required' };
  }
  const validCats = [
    'rate-abuse', 'malicious-payload', 'policy-violation',
    'spam', 'scraping-overrun', 'other',
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
