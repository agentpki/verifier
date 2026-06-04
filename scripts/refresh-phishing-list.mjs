#!/usr/bin/env node
// Refresh the curated phishing-domain list from public threat feeds.
//
// Generates:
//   src/phishing-domains.generated.ts
//
// Sources (all free, no auth required):
//   1. PhishStats free CSV feed   — https://phishstats.info/phish_score.csv
//      Score 0..10; we keep score ≥ MIN_SCORE (default 6 = high-confidence).
//   2. OpenPhish free feed        — https://openphish.com/feed.txt
//      ~500 most-recent phishing URLs (free version is rate-limited).
//   3. URLhaus by abuse.ch        — https://urlhaus.abuse.ch/downloads/text/
//      Malware-distribution URLs (a portion are phishing-adjacent).
//
// Each source returns URLs; we extract the hostname, lowercase, dedupe.
//
// Usage:
//   node scripts/refresh-phishing-list.mjs        # writes generated TS
//   node scripts/refresh-phishing-list.mjs --dry  # prints stats, no write
//
// Recommended cadence: daily via GitHub Actions cron. PhishStats data
// rolls hourly; OpenPhish's free feed updates ~30min. Running once a
// day gives a fresh-enough list without hammering anyone.
//
// Generated file is import-only — heuristic.ts merges it with the
// hand-curated KNOWN_PHISHING_DOMAINS Set, so an external feed outage
// never wipes our baseline coverage.

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const outPath = join(root, 'src', 'phishing-domains.generated.ts');

// PhishStats score threshold. 0..10 scale; 6+ is "high confidence
// phishing" per their docs. Lower threshold = more coverage but more
// false positives.
const MIN_SCORE = 6;

// Hard cap on total domains in the generated set. KV value limit is
// 25 MB; a 5k-entry Set of 30-char domains serialises to ~200 KB.
// Keeping it lower also keeps the worker bundle small.
const MAX_DOMAINS = 5000;

const FEEDS = {
  phishstats: 'https://phishstats.info/phish_score.csv',
  openphish:  'https://openphish.com/feed.txt',
  urlhaus:    'https://urlhaus.abuse.ch/downloads/text/',
};

const DRY = process.argv.includes('--dry');

function extractDomain(url) {
  if (!url) return null;
  const trimmed = url.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  try {
    const u = new URL(trimmed.includes('://') ? trimmed : 'http://' + trimmed);
    const host = u.hostname.toLowerCase();
    // Skip IP addresses, localhost variants, and obviously bogus values
    if (!host.includes('.')) return null;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return null;
    if (host === 'localhost' || host.endsWith('.local')) return null;
    return host;
  } catch {
    return null;
  }
}

async function fetchPhishStats() {
  process.stdout.write(`  fetching PhishStats (${FEEDS.phishstats})…`);
  try {
    const res = await fetch(FEEDS.phishstats, { headers: { 'user-agent': 'agentpki-refresh-phishing/1.0' } });
    if (!res.ok) {
      console.log(`  HTTP ${res.status} — skipping`);
      return new Set();
    }
    const csv = await res.text();
    const domains = new Set();
    let kept = 0, skipped = 0;
    // PhishStats format: "score","date","url","ip","country","asn","source"
    // The first line is sometimes a comment block — skip lines starting with #
    for (const line of csv.split('\n')) {
      if (!line || line.startsWith('#')) continue;
      // Tolerant CSV parse — fields are quoted, comma-separated
      const fields = line.match(/"([^"]*)"/g);
      if (!fields || fields.length < 3) continue;
      const score = parseFloat(fields[0].slice(1, -1));
      const url = fields[2].slice(1, -1);
      if (!isFinite(score)) continue;
      if (score < MIN_SCORE) { skipped++; continue; }
      const host = extractDomain(url);
      if (host) { domains.add(host); kept++; }
    }
    console.log(`  ✓ ${kept} domains (filtered ${skipped} below score ${MIN_SCORE})`);
    return domains;
  } catch (e) {
    console.log(`  failed: ${e.message}`);
    return new Set();
  }
}

async function fetchOpenPhish() {
  process.stdout.write(`  fetching OpenPhish (${FEEDS.openphish})…`);
  try {
    const res = await fetch(FEEDS.openphish, { headers: { 'user-agent': 'agentpki-refresh-phishing/1.0' } });
    if (!res.ok) {
      console.log(`  HTTP ${res.status} — skipping`);
      return new Set();
    }
    const text = await res.text();
    const domains = new Set();
    for (const line of text.split('\n')) {
      const host = extractDomain(line);
      if (host) domains.add(host);
    }
    console.log(`  ✓ ${domains.size} domains`);
    return domains;
  } catch (e) {
    console.log(`  failed: ${e.message}`);
    return new Set();
  }
}

async function fetchURLhaus() {
  process.stdout.write(`  fetching URLhaus (${FEEDS.urlhaus})…`);
  try {
    const res = await fetch(FEEDS.urlhaus, { headers: { 'user-agent': 'agentpki-refresh-phishing/1.0' } });
    if (!res.ok) {
      console.log(`  HTTP ${res.status} — skipping`);
      return new Set();
    }
    const text = await res.text();
    const domains = new Set();
    for (const line of text.split('\n')) {
      const host = extractDomain(line);
      if (host) domains.add(host);
    }
    console.log(`  ✓ ${domains.size} domains`);
    return domains;
  } catch (e) {
    console.log(`  failed: ${e.message}`);
    return new Set();
  }
}

async function main() {
  console.log('Refreshing AgentPKI phishing-domain list');
  console.log('=========================================\n');

  const [ps, op, uh] = await Promise.all([
    fetchPhishStats(),
    fetchOpenPhish(),
    fetchURLhaus(),
  ]);

  const all = new Set();
  for (const d of ps) all.add(d);
  for (const d of op) all.add(d);
  for (const d of uh) all.add(d);

  console.log(`\nAfter dedupe: ${all.size} unique domains`);

  // Sort + cap
  const sorted = [...all].sort();
  const final = sorted.slice(0, MAX_DOMAINS);
  if (sorted.length > MAX_DOMAINS) {
    console.log(`Capping at ${MAX_DOMAINS} (dropped ${sorted.length - MAX_DOMAINS})`);
  }

  if (DRY) {
    console.log('\n--dry: not writing file. Sample (first 10):');
    for (const d of final.slice(0, 10)) console.log('  ' + d);
    return;
  }

  const ts = new Date().toISOString();
  const ymd = ts.slice(0, 10);
  const content = `// ════════════════════════════════════════════════════════════════════
// AUTO-GENERATED — DO NOT EDIT BY HAND.
// Regenerate via: pnpm refresh-phishing
//
// Generated:  ${ts}
// Sources:    PhishStats (score ≥ ${MIN_SCORE}), OpenPhish, URLhaus
// Count:      ${final.length} unique domains
//
// The hand-curated baseline lives in src/heuristic.ts so an upstream
// outage never wipes coverage. This generated Set is merged onto it.
// ════════════════════════════════════════════════════════════════════

/* eslint-disable */
export const GENERATED_PHISHING_DOMAINS: ReadonlySet<string> = new Set([
${final.map(d => `  ${JSON.stringify(d)},`).join('\n')}
]);

export const GENERATED_PHISHING_METADATA = {
  generated_at: ${JSON.stringify(ts)},
  generated_on: ${JSON.stringify(ymd)},
  source_count: 3,
  domain_count: ${final.length},
} as const;
`;

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, content);
  console.log(`\n✓ Wrote ${final.length} domains to ${outPath.replace(root + '\\', '').replace(root + '/', '')}`);
  console.log(`  Generated at: ${ts}`);
}

main().catch((err) => {
  console.error('\n✗ FAILED:', err.message);
  process.exit(1);
});
