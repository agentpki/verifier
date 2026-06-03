// Weighting table for abuse-report severities. Shared between abuse.ts
// (when bumping the per-jti summary counter) and directory.ts (when
// computing the reputation score from the summary). Single source of
// truth — diverging weights here would silently corrupt scoring.
//
// Curve rationale: 5 medium reports → reputation_score ~0.6 ("Many
// reports"), 3 critical → ~0.6, 1 low → ~0.02 ("Clean"). Matches the
// labels in the extension popup so a few low-severity nuisance reports
// don't push a passport into Red unjustly.

export const SEVERITY_WEIGHT: Record<string, number> = {
  low: 0.1,
  medium: 0.3,
  high: 0.6,
  critical: 1.0,
};

/** Squash a cumulative weighted-sum to a 0..1 reputation score. */
export function weightedSumToScore(weightedSum: number): number {
  // 1 - e^(-x/6): 1 medium = 0.05, 5 medium = 0.57, 15 medium = 0.92
  return Math.round(Math.min(1, 1 - Math.exp(-weightedSum / 6)) * 100) / 100;
}
