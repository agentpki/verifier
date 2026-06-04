// Heuristic checks for unverified-agent inputs.
//
// Called from agentpki.dev/check when /v1/verify returns "no passport found"
// and we want to give the user SOMETHING actionable. Each heuristic is a
// separate signal — none of them turn a yellow card green. The UI shows
// status per-check, including a candid "not_available" state when an
// external API isn't configured (e.g. Google Safe Browsing key absent).
//
// What's checked:
//   - Domain reputation:
//       1. internal abuse list (ABUSE_REPORTS KV, `domain-abuse:<domain>`)
//       2. hardcoded known-phishing list (this file, curated)
//       3. Google Safe Browsing (only if SAFE_BROWSING_KEY env is set)
//   - Phone reputation:
//       1. internal community list (ABUSE_REPORTS KV, `phone-abuse:<phone>`)
//   - Community reports:
//       1. count of reports against this identifier in the last 30 days
//
// Identifier types extracted from input:
//   - Domain (from raw domain or URL hostname)
//   - Phone number (E.164-ish: + then 10–15 digits)
//   - Email (only the domain part participates in the domain check)
//
// All responses include `disclaimer: "heuristic_not_proof"` so downstream
// UIs are forced to treat results as signals, not verification.

export interface HeuristicBindings {
  ABUSE_REPORTS?: KVNamespace;
  SAFE_BROWSING_KEY?: string;
}

// Curated list of well-known phishing/typosquat domains based on public
// reports (PhishTank, OpenPhish, URLhaus aggregations). NOT exhaustive —
// paired with the internal abuse KV which grows from user reports without
// requiring a deploy.
//
// To refresh from a real data feed: see scripts/refresh-phishing-list.mjs
// (TBD) — downloads from PhishTank's open CSV and regenerates this Set.
const KNOWN_PHISHING_DOMAINS = new Set([
  // ─── Microsoft typo-squats / fake support ─────
  'micros0ft-support.com',
  'micros0ft-login.com',
  'microsft-help.com',
  'microsoftt-support.com',
  'microsoftlogin-security.com',
  'office365-renewal.com',
  'live-account-verify.com',
  'outlook-account-recovery.com',
  // ─── Apple typo-squats ─────
  'app1e-account.com',
  'appleid-verify.com',
  'apple-id-security.com',
  'icloud-account-locked.com',
  'apple-pay-verification.com',
  // ─── PayPal typo-squats ─────
  'paypa1-security.com',
  'paypal-verify-account.com',
  'paypal-account-suspended.com',
  'paypa1-resolution-center.com',
  // ─── Amazon typo-squats ─────
  'amazon-refund-center.com',
  'amaz0n-orders.com',
  'amazon-account-security.com',
  'amzn-package-tracking.com',
  // ─── Bank / financial typo-squats ─────
  'chase-online-verify.com',
  'bofa-account-alert.com',
  'wellsfargo-secure-login.com',
  'citi-fraud-alert.com',
  // ─── Crypto wallet / exchange typo-squats ─────
  'metamask-verify.com',
  'metamask-recovery.com',
  'coinbase-support-help.com',
  'binance-security-alert.com',
  'ledger-live-recover.com',
  'trezor-recovery-seed.com',
  // ─── Government / tax / SSA scams ─────
  'irs-refund-status.com',
  'social-security-claim.com',
  'us-tax-refund.com',
  // ─── Generic 'tech support' scams ─────
  'macsecurity-alert.com',
  'windows-defender-alert.com',
  'pc-virus-removal.com',
]);

interface CheckResult {
  name: string;
  source: string;
  status: 'clean' | 'flagged' | 'not_available' | 'inconclusive';
  detail?: string;
  data?: Record<string, unknown>;
}

interface ExtractedIdentifiers {
  domain?: string;
  phone?: string;
  email?: string;
  raw: string;
}

function extract(input: string): ExtractedIdentifiers {
  const out: ExtractedIdentifiers = { raw: input.trim() };
  if (!out.raw) return out;

  // Email — try first because it gives us a clean domain via @
  const emailMatch = out.raw.match(/([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i);
  if (emailMatch && emailMatch[1]) {
    out.email = emailMatch[1].toLowerCase();
    const dom = emailMatch[1].split('@')[1];
    if (dom) out.domain = dom.toLowerCase();
  }

  // URL or domain — only if email didn't already give us one
  if (!out.domain) {
    try {
      const u = new URL(out.raw.includes('://') ? out.raw : 'https://' + out.raw);
      if (u.hostname.includes('.')) out.domain = u.hostname.toLowerCase();
    } catch {
      // Not parseable — fall through to regex
    }
  }

  // Bare-domain regex — find a `<word>.<tld>` pattern ANYWHERE in the input,
  // not just at word boundaries. Catches embedded domains like the one in
  // `agent:example.com/some-bot` which the URL parser mishandles.
  // The TLD must be 2–24 letters (covers .com through .technology, but not
  // arbitrary numeric runs like agent:foo:1234).
  if (!out.domain) {
    const m = out.raw.match(/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24})/i);
    if (m && m[1] && m[1].includes('.')) {
      out.domain = m[1].toLowerCase();
    }
  }

  // Phone (E.164-ish): + then 10–15 digits, allowing spaces/dashes/parens
  const phoneMatch = out.raw.replace(/[\s\-()]/g, '').match(/(\+?\d{10,15})/);
  if (phoneMatch && phoneMatch[1]) out.phone = phoneMatch[1].startsWith('+') ? phoneMatch[1] : '+' + phoneMatch[1];

  return out;
}

async function checkInternalAbuse(
  kv: KVNamespace,
  prefix: string,
  identifier: string,
): Promise<CheckResult> {
  try {
    // KV.list with prefix to find all reports against this identifier
    const listing = await kv.list({
      prefix: `${prefix}:${identifier}:`,
      limit: 50,
    });
    const count = listing.keys.length;
    if (count === 0) {
      return { name: prefix.replace('-abuse', '_reputation'), source: 'internal', status: 'clean', detail: 'No abuse reports filed against this identifier.' };
    }
    return {
      name: prefix.replace('-abuse', '_reputation'),
      source: 'internal',
      status: 'flagged',
      detail: `${count} abuse report${count === 1 ? '' : 's'} filed against this identifier in the AgentPKI community database.`,
      data: { count },
    };
  } catch (e) {
    return { name: prefix.replace('-abuse', '_reputation'), source: 'internal', status: 'inconclusive', detail: 'Internal abuse lookup failed.' };
  }
}

function checkHardcodedPhishing(domain: string): CheckResult {
  if (KNOWN_PHISHING_DOMAINS.has(domain)) {
    return {
      name: 'domain_reputation',
      source: 'agentpki_curated_phishing_list',
      status: 'flagged',
      detail: 'This domain appears on AgentPKI\'s curated list of known phishing sites.',
    };
  }
  return {
    name: 'domain_reputation',
    source: 'agentpki_curated_phishing_list',
    status: 'clean',
    detail: 'Not on AgentPKI\'s curated phishing list (curation is not exhaustive).',
  };
}

async function checkSafeBrowsing(domain: string, key: string | undefined): Promise<CheckResult> {
  if (!key) {
    return {
      name: 'domain_reputation',
      source: 'google_safe_browsing',
      status: 'not_available',
      detail: 'Google Safe Browsing not configured for this deployment. Operators can add an API key to enable this check.',
    };
  }
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'agentpki-verifier', clientVersion: '0.2' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: 'https://' + domain }],
        },
      }),
    });
    if (!res.ok) {
      return {
        name: 'domain_reputation',
        source: 'google_safe_browsing',
        status: 'inconclusive',
        detail: `Safe Browsing returned HTTP ${res.status}.`,
      };
    }
    const body = (await res.json()) as { matches?: unknown[] };
    if (Array.isArray(body.matches) && body.matches.length > 0) {
      return {
        name: 'domain_reputation',
        source: 'google_safe_browsing',
        status: 'flagged',
        detail: 'Google Safe Browsing reports this domain as malicious.',
        data: { matches: body.matches.length },
      };
    }
    return {
      name: 'domain_reputation',
      source: 'google_safe_browsing',
      status: 'clean',
      detail: 'Not on Google Safe Browsing threat lists.',
    };
  } catch (e) {
    return {
      name: 'domain_reputation',
      source: 'google_safe_browsing',
      status: 'inconclusive',
      detail: 'Safe Browsing lookup failed (network or quota).',
    };
  }
}

export async function handleHeuristicCheck(req: Request, env: HeuristicBindings): Promise<Response> {
  let body: { input?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch (e) {
    return json(
      { error: 'malformed_json', detail: e instanceof Error ? e.message : String(e) },
      400,
    );
  }
  if (!body.input || typeof body.input !== 'string') {
    return json({ error: 'missing_input', detail: 'input field is required and must be a string' }, 400);
  }

  const ids = extract(body.input);
  const checks: CheckResult[] = [];

  if (!ids.domain && !ids.phone) {
    return json({
      v: 1,
      input: body.input.slice(0, 256),
      extracted: ids,
      checks: [],
      disclaimer: 'heuristic_not_proof',
      note: 'Could not extract a domain or phone number from the input. Nothing to check.',
    });
  }

  // Domain checks
  if (ids.domain) {
    checks.push(checkHardcodedPhishing(ids.domain));
    if (env.ABUSE_REPORTS) {
      checks.push(await checkInternalAbuse(env.ABUSE_REPORTS, 'domain-abuse', ids.domain));
    }
    checks.push(await checkSafeBrowsing(ids.domain, env.SAFE_BROWSING_KEY));
  }

  // Phone checks
  if (ids.phone) {
    if (env.ABUSE_REPORTS) {
      checks.push(await checkInternalAbuse(env.ABUSE_REPORTS, 'phone-abuse', ids.phone));
    } else {
      checks.push({
        name: 'phone_reputation',
        source: 'internal',
        status: 'not_available',
        detail: 'Phone-reputation database not configured for this deployment.',
      });
    }
  }

  // Compute an overall verdict from the per-source checks so the UI can
  // present a single clear summary at the top of the heuristics block.
  // Rules:
  //   - any FLAGGED → overall: flagged (highest precedence)
  //   - else any CLEAN result + 0 flagged → overall: clean
  //   - else all not_available / inconclusive → overall: inconclusive
  const flaggedCount = checks.filter((c) => c.status === 'flagged').length;
  const cleanCount   = checks.filter((c) => c.status === 'clean').length;
  const naCount      = checks.filter((c) => c.status === 'not_available').length;
  const incCount     = checks.filter((c) => c.status === 'inconclusive').length;
  let overall: 'flagged' | 'clean' | 'inconclusive';
  let overallSummary: string;
  if (flaggedCount > 0) {
    overall = 'flagged';
    overallSummary = `This identifier was flagged by ${flaggedCount} of ${checks.length} heuristic source${checks.length === 1 ? '' : 's'}. Treat with extra caution.`;
  } else if (cleanCount > 0) {
    overall = 'clean';
    overallSummary = `No heuristic source flagged this identifier (${cleanCount} clean, ${naCount} not available${incCount ? ', ' + incCount + ' inconclusive' : ''}). Heuristics are signals, not proof — still apply normal caution.`;
  } else {
    overall = 'inconclusive';
    overallSummary = `Heuristic results inconclusive (${naCount} sources unavailable). Apply normal caution for any unverified agent.`;
  }

  return json({
    v: 1,
    input: body.input.slice(0, 256),
    extracted: ids,
    overall,
    overall_summary: overallSummary,
    checks,
    disclaimer: 'heuristic_not_proof',
  }, 200, { 'Cache-Control': 'public, max-age=300, stale-while-revalidate=900' });
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extra },
  });
}
