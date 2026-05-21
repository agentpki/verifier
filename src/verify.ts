// AgentPKI verification — implements the 12-step procedure of spec §8.2.
//
// Returns the structured verdict described in §8.1.2. The handler is pure (no
// I/O outside fetch for directory resolution + cache reads) so it can run in
// any Cloudflare Worker isolate.

import {
  parsePassport,
  verifyPassport,
  resolveIssuerDirectory,
  selectKey,
  decodePublicKey,
  verifyRequestSignature,
  IssuerDirectoryError,
  util as sdkUtil,
  type FailureReason,
  type IssuerDirectory,
  type TrustTier,
} from '@agentpki/sdk';
import { getCachedDirectory, setCachedDirectory } from './cache.js';
import { applyPolicy, type SitePolicy, type PolicyMatch } from './policy.js';

export interface VerifyRequestBody {
  token: string;
  mode?: 'A' | 'B';
  request?: {
    method: string;
    url: string;
    body_sha256?: string | null;
    signature_input?: string;
    signature?: string;
  };
  site_policy?: SitePolicy;
}

export interface VerifyResponse {
  verified: boolean;
  verdict: 'allow' | 'throttle' | 'deny' | 'unknown';
  passport?: {
    issuer: string;
    issuer_name?: string;
    agent_id: string;
    scopes: string[];
    tier: TrustTier;
    issued_at: number;
    expires_at: number;
    jti: string;
  };
  abuse_score?: number;
  rate_limit?: { rpm?: number; daily?: number };
  policy_match?: PolicyMatch;
  failure_reason?: FailureReason;
  failure_detail?: string;
  cached_until?: number;
  verifier_id: string;
}

const VERIFIER_ID = 'agentpki-verifier-edge';
const ABUSE_SCORE_PLACEHOLDER = 0.0; // v0.2: real aggregation

export async function verifyPassportEdge(body: VerifyRequestBody): Promise<VerifyResponse> {
  const now = Math.floor(Date.now() / 1000);

  if (!body.token || typeof body.token !== 'string') {
    return failed('malformed', 'missing or non-string `token`');
  }

  // Step 1-2: parse token to peek at iss and footer.kid (NOT trusted yet)
  let parsed;
  try {
    parsed = parsePassport(body.token);
  } catch (e) {
    return failed('malformed', e instanceof Error ? e.message : String(e));
  }

  const payload = parsed.payload;
  const kid = parsed.footer?.kid;

  // Step 3: resolve issuer directory (cache → fetch)
  let directory: IssuerDirectory;
  const cached = getCachedDirectory(payload.iss);
  if (cached) {
    directory = cached;
  } else {
    try {
      directory = await resolveIssuerDirectory(payload.iss);
    } catch (e) {
      if (e instanceof IssuerDirectoryError) {
        return failed('unknown_issuer', e.message);
      }
      return failed('unknown_issuer', e instanceof Error ? e.message : String(e));
    }
    setCachedDirectory(payload.iss, directory);
  }

  // Step 4: select pubkey by kid (or fallback)
  const sel = selectKey(directory, kid, now);
  if (sel.status === 'revoked') {
    return failed(
      'revoked_key',
      `kid="${sel.kid}" revoked at ${sel.revokedAt} (${sel.reason})`,
    );
  }
  if (sel.status === 'not_found') {
    return failed('bad_signature', sel.reason);
  }

  let publicKey: Uint8Array;
  try {
    publicKey = decodePublicKey(sel.key.pubkey);
  } catch (e) {
    return failed(
      'bad_signature',
      `pubkey decode failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // Steps 5-7: signature + temporal checks (SDK handles this)
  const verifyRes = verifyPassport(body.token, publicKey, {
    expectedIssuer: payload.iss,
    now,
  });
  if (!verifyRes.valid) {
    return failed(verifyRes.failureReason ?? 'bad_signature', verifyRes.failureDetail);
  }

  // Step 7 (audience): check site domain against passport.aud
  // Note: site_policy doesn't currently carry the site domain explicitly;
  // we leave audience checks to the relying site for v0.1 if aud === "*".
  if (payload.aud && payload.aud !== '*') {
    // Without an explicit "expected audience" in the request, we accept any
    // non-"*" aud passport as valid. Relying sites SHOULD verify aud
    // matches their own domain after receiving this verdict.
  }

  // Step 8: revocation list (CRL) — v0.1 stub.
  // Production: fetch directory.crl_url, build/refresh Bloom filter, do
  // exact-match check when Bloom is positive. See spec §10.3.
  // Skipped here to keep v0.1 deploy simple; documented as a known gap.

  // Step 9: Mode B signature
  if (body.mode === 'B') {
    const sigCheck = await verifyModeBSignature(body, payload, now);
    if (!sigCheck.ok) {
      return failed(sigCheck.reason, sigCheck.detail);
    }
  }

  // Step 10: apply site policy
  const policy = body.site_policy;
  const policyMatch = policy
    ? applyPolicy(policy, {
        tier: payload.tier,
        scope: payload.scope ?? [],
        abuseScore: ABUSE_SCORE_PLACEHOLDER,
        mode: body.mode ?? 'A',
      })
    : undefined;

  // Step 11: verdict
  let verdict: 'allow' | 'throttle' | 'deny' = 'allow';
  let failReason: FailureReason | undefined;
  let failDetail: string | undefined;

  if (policyMatch && !policyMatch.allPassed) {
    verdict = 'deny';
    if (!policyMatch.minTier) {
      failReason = 'tier_too_low';
      failDetail = `passport.tier=${payload.tier} < policy.min_tier=${policy?.min_tier}`;
    } else if (!policyMatch.scopes) {
      failReason = 'missing_scope';
      failDetail = 'required scope(s) not present in passport';
    } else if (!policyMatch.abuse) {
      failReason = 'abuse_threshold_exceeded';
    } else if (!policyMatch.signedMode) {
      failReason = 'signature_mode_required';
    } else if (!policyMatch.allowT1) {
      failReason = 'tier_too_low';
      failDetail = 'site_policy rejects T1 passports';
    }
  }

  const response: VerifyResponse = {
    verified: verdict !== 'deny',
    verdict,
    passport: {
      issuer: payload.iss,
      issuer_name: directory.name,
      agent_id: payload.sub,
      scopes: payload.scope ?? [],
      tier: payload.tier,
      issued_at: payload.iat,
      expires_at: payload.exp,
      jti: payload.jti,
    },
    abuse_score: ABUSE_SCORE_PLACEHOLDER,
    cached_until: Math.min(payload.exp, now + 60),
    verifier_id: VERIFIER_ID,
  };
  if (payload.rate) response.rate_limit = payload.rate;
  if (policyMatch) response.policy_match = policyMatch;
  if (failReason) {
    response.failure_reason = failReason;
    if (failDetail) response.failure_detail = failDetail;
  }

  return response;
}

async function verifyModeBSignature(
  body: VerifyRequestBody,
  payload: ReturnType<typeof parsePassport>['payload'],
  now: number,
): Promise<{ ok: true } | { ok: false; reason: FailureReason; detail: string }> {
  if (!body.request) {
    return { ok: false, reason: 'signature_mode_required', detail: 'Mode B requires `request` field' };
  }
  const { signature, signature_input, method, url, body_sha256 } = body.request;
  if (!signature || !signature_input) {
    return {
      ok: false,
      reason: 'signature_mode_required',
      detail: 'Mode B requires request.signature and request.signature_input',
    };
  }

  const meta = parseSignatureInput(signature_input);
  if (!meta) {
    return { ok: false, reason: 'signature_invalid', detail: 'cannot parse signature-input' };
  }
  if (meta.created > now + 60 || meta.expires < now) {
    return {
      ok: false,
      reason: 'signature_invalid',
      detail: `signature window invalid: created=${meta.created} expires=${meta.expires} now=${now}`,
    };
  }
  if (meta.expires - meta.created > 300) {
    return {
      ok: false,
      reason: 'signature_invalid',
      detail: 'signature window exceeds 300s maximum',
    };
  }

  const cnfX = payload.cnf?.jwk?.x;
  if (typeof cnfX !== 'string') {
    return {
      ok: false,
      reason: 'signature_invalid',
      detail: 'passport has no cnf.jwk.x for Mode B verification',
    };
  }

  let cnfPub: Uint8Array;
  try {
    cnfPub = sdkUtil.base64urlDecode(cnfX);
  } catch (e) {
    return {
      ok: false,
      reason: 'signature_invalid',
      detail: `cannot decode cnf.jwk.x: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  const components: { method: string; url: string; bodySha256?: string } = { method, url };
  if (body_sha256) components.bodySha256 = body_sha256;

  const sigOk = verifyRequestSignature(
    components,
    { created: meta.created, expires: meta.expires, keyid: body.token, alg: 'ed25519' },
    cnfPub,
    signature,
  );
  if (!sigOk) {
    return { ok: false, reason: 'signature_invalid', detail: 'RFC 9421 signature did not verify' };
  }

  return { ok: true };
}

function parseSignatureInput(sigInput: string): { created: number; expires: number } | null {
  const createdMatch = sigInput.match(/created=(\d+)/);
  const expiresMatch = sigInput.match(/expires=(\d+)/);
  if (!createdMatch?.[1] || !expiresMatch?.[1]) return null;
  return {
    created: parseInt(createdMatch[1], 10),
    expires: parseInt(expiresMatch[1], 10),
  };
}

function failed(reason: FailureReason, detail?: string): VerifyResponse {
  const r: VerifyResponse = {
    verified: false,
    verdict: 'deny',
    failure_reason: reason,
    verifier_id: VERIFIER_ID,
  };
  if (detail) r.failure_detail = detail;
  return r;
}
