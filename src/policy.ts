// Site policy enforcement per spec §8.1.1.
//
// A site policy is a declarative gate the relying site attaches to its
// verification request. The verifier evaluates each clause and reports which
// passed.

import type { TrustTier } from '@agentpki/sdk';

export interface SitePolicy {
  /** Minimum trust tier required (1, 2, or 3). */
  min_tier?: TrustTier;
  /** All listed scopes MUST be present in passport.scope. */
  required_scopes?: string[];
  /** Reject if abuse_score > this value. Float in [0, 1]. */
  max_abuse_score?: number;
  /** If true, require Mode B (signed) verification. */
  require_signed?: boolean;
  /** If false, T1 (DNS-only) issuers are rejected even if tier matches. */
  allow_t1?: boolean;
}

export interface PolicyContext {
  tier: TrustTier;
  scope: string[];
  abuseScore: number;
  mode: 'A' | 'B';
}

export interface PolicyMatch {
  minTier: boolean;
  scopes: boolean;
  abuse: boolean;
  signedMode: boolean;
  allowT1: boolean;
  allPassed: boolean;
}

export function applyPolicy(policy: SitePolicy, ctx: PolicyContext): PolicyMatch {
  const minTier = policy.min_tier === undefined ? true : ctx.tier >= policy.min_tier;

  const scopes =
    !policy.required_scopes || policy.required_scopes.length === 0
      ? true
      : policy.required_scopes.every((s) => ctx.scope.includes(s));

  const abuse =
    policy.max_abuse_score === undefined ? true : ctx.abuseScore <= policy.max_abuse_score;

  const signedMode = !policy.require_signed || ctx.mode === 'B';

  const allowT1 = policy.allow_t1 === false ? ctx.tier !== 1 : true;

  return {
    minTier,
    scopes,
    abuse,
    signedMode,
    allowT1,
    allPassed: minTier && scopes && abuse && signedMode && allowT1,
  };
}
