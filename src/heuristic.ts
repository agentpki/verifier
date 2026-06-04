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

// Small curated list of well-known phishing/scam domains. Grows over time
// via PRs to this file. Not exhaustive — paired with the internal abuse
// KV which can be populated from user reports without a deploy.
const KNOWN_PHISHING_DOMAINS = new Set([
  // Common typo-squats of real brands
  'micros0ft-support.com',
  'app1e-account.com',
  'paypa1-security.com',
  'amazon-refund-center.com',
  // Add more as they're confirmed
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

  // URL or domain
  try {
    const u = new URL(out.raw.includes('://') ? out.raw : 'https://' + out.raw);
    if (u.hostname.includes('.')) out.domain = u.hostname.toLowerCase();
  } catch {
    // Not a URL — try bare domain regex
    const m = out.raw.match(/(?:^|\s)([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:\s|$)/i);
    if (m && m[1]) out.domain = m[1].toLowerCase();
  }

  // Phone (E.164-ish): + then 10–15 digits, allowing spaces/dashes/parens
  const phoneMatch = out.raw.replace(/[\s\-()]/g, '').match(/(\+?\d{10,15})/);
  if (phoneMatch && phoneMatch[1]) out.phone = phoneMatch[1].startsWith('+') ? phoneMatch[1] : '+' + phoneMatch[1];

  // Email
  const emailMatch = out.raw.match(/([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i);
  if (emailMatch && emailMatch[1]) {
    out.email = emailMatch[1].toLowerCase();
    // Use the email domain for the domain check too if no domain was set
    if (!out.domain) {
      const dom = emailMatch[1].split('@')[1];
      if (dom) out.domain = dom.toLowerCase();
    }
  }

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

  return json({
    v: 1,
    input: body.input.slice(0, 256),
    extracted: ids,
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
