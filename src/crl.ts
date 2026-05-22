// Certificate Revocation List (CRL) handling per spec §10.
//
// Each issuer publishes a CRL at `crl_url` (declared in their directory
// document). We fetch it, cache it in KV with a TTL based on `next_update`,
// and consult it on every verification.
//
// v0.2 uses a simple linear-scan Set lookup over revoked jti values. This is
// adequate for CRLs with <10k entries (typical for an active issuer).
// v0.3 will swap to a Bloom-filter representation with delta updates per
// spec §10.3.

export interface CrlEntry {
  jti: string;
  revoked_at: number;
  reason: string;
}

export interface Crl {
  v: 1;
  issuer: string;
  generated_at: number;
  next_update: number;
  revoked: CrlEntry[];
  signature?: string; // PASETO-signed by issuer (optional in v0.1)
}

export interface CrlBindings {
  CRL_CACHE?: KVNamespace;
}

export interface RevocationCheck {
  revoked: boolean;
  reason?: string;
  revoked_at?: number;
  crl_fresh: boolean;
}

const MIN_TTL = 60;       // never cache for less than 1 minute
const MAX_TTL = 3600;     // never cache for more than 1 hour
const FETCH_TIMEOUT_MS = 1500;

/**
 * Check whether a passport's jti is revoked per the issuer's published CRL.
 *
 * Strategy:
 *   1. Look up cached CRL in KV.
 *   2. If absent or stale (now > next_update), fetch fresh.
 *   3. Scan for the jti.
 *
 * Returns `revoked: false, crl_fresh: false` if CRL can't be loaded — the
 * verifier MUST treat unknown CRL state as "not revoked" so a transient
 * failure doesn't block legitimate traffic. Defense-in-depth: passports are
 * short-lived (≤ 24h) and the issuer-key rotation provides additional
 * compromise-recovery.
 */
export async function checkRevocation(
  jti: string,
  crlUrl: string | undefined,
  issuer: string,
  env: CrlBindings,
): Promise<RevocationCheck> {
  if (!crlUrl) {
    return { revoked: false, crl_fresh: false };
  }

  const crl = await fetchCrl(issuer, crlUrl, env);
  if (!crl) {
    return { revoked: false, crl_fresh: false };
  }

  const entry = crl.revoked.find((e) => e.jti === jti);
  if (entry) {
    return {
      revoked: true,
      reason: entry.reason,
      revoked_at: entry.revoked_at,
      crl_fresh: true,
    };
  }
  return { revoked: false, crl_fresh: true };
}

async function fetchCrl(
  issuer: string,
  crlUrl: string,
  env: CrlBindings,
): Promise<Crl | null> {
  // Tier 1: KV cache
  if (env.CRL_CACHE) {
    try {
      const cached = await env.CRL_CACHE.get(kvKey(issuer), 'json');
      if (cached) return cached as Crl;
    } catch {
      // fall through to origin fetch
    }
  }

  // Tier 2: origin fetch
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  let crl: Crl | null = null;
  try {
    const res = await fetch(crlUrl, {
      headers: { Accept: 'application/json' },
      signal: ctl.signal,
    });
    if (!res.ok) return null;
    crl = (await res.json()) as Crl;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }

  // Validate basic shape
  if (!crl || crl.v !== 1 || crl.issuer !== issuer || !Array.isArray(crl.revoked)) {
    return null;
  }

  // Cache in KV with TTL clamped to [MIN_TTL, MAX_TTL]
  if (env.CRL_CACHE) {
    const now = Math.floor(Date.now() / 1000);
    const naturalTtl = Math.max(0, crl.next_update - now);
    const ttl = Math.max(MIN_TTL, Math.min(MAX_TTL, naturalTtl));
    try {
      await env.CRL_CACHE.put(kvKey(issuer), JSON.stringify(crl), {
        expirationTtl: ttl,
      });
    } catch {
      // KV write failure not fatal
    }
  }

  return crl;
}

function kvKey(issuer: string): string {
  return `crl:${issuer}`;
}
