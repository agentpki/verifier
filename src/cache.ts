// Issuer directory cache — KV-backed (cross-isolate) with in-memory hot-path.
//
// v0.2: persists across Worker isolates via Cloudflare KV when bound.
// Falls back to per-isolate in-memory cache if KV binding is absent.
//
// Two-tier read path:
//   1. Memory cache (≤ 1ms, but only this isolate)
//   2. KV cache (~10-30ms, shared across all isolates)
//   3. Origin fetch (~50-200ms, last resort)

import type { IssuerDirectory } from '@agentpki/sdk';

interface CacheEntry {
  doc: IssuerDirectory;
  fetchedAt: number;
  expiresAt: number;
}

const DEFAULT_TTL = 300; // 5 minutes — matches spec §6.1 Cache-Control hint

// Per-isolate hot cache. Persists for the isolate's lifetime (minutes-hours).
const memCache = new Map<string, CacheEntry>();

export interface CacheBindings {
  ISSUER_CACHE?: KVNamespace;
}

export async function getCachedDirectory(
  issuer: string,
  env: CacheBindings = {},
): Promise<IssuerDirectory | null> {
  const now = Math.floor(Date.now() / 1000);

  // Tier 1: memory cache (this isolate only)
  const memEntry = memCache.get(issuer);
  if (memEntry && memEntry.expiresAt > now) {
    return memEntry.doc;
  }

  // Tier 2: KV cache (shared across all isolates)
  if (env.ISSUER_CACHE) {
    try {
      const raw = await env.ISSUER_CACHE.get(kvKey(issuer), 'json');
      if (raw) {
        const doc = raw as IssuerDirectory;
        // Re-populate hot cache for this isolate
        memCache.set(issuer, { doc, fetchedAt: now, expiresAt: now + DEFAULT_TTL });
        return doc;
      }
    } catch {
      // KV transient errors — fall through to fresh fetch
    }
  }

  // If memory entry expired, evict
  if (memEntry) memCache.delete(issuer);

  return null;
}

export async function setCachedDirectory(
  issuer: string,
  doc: IssuerDirectory,
  ttlSeconds: number = DEFAULT_TTL,
  env: CacheBindings = {},
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);

  // Always populate memory
  memCache.set(issuer, { doc, fetchedAt: now, expiresAt: now + ttlSeconds });

  // And KV if bound
  if (env.ISSUER_CACHE) {
    try {
      await env.ISSUER_CACHE.put(kvKey(issuer), JSON.stringify(doc), {
        expirationTtl: Math.max(60, ttlSeconds),
      });
    } catch {
      // KV write failure isn't fatal — memory cache still serves
    }
  }
}

export function cacheStats(): { size: number; issuers: string[] } {
  return { size: memCache.size, issuers: [...memCache.keys()] };
}

function kvKey(issuer: string): string {
  return `dir:${issuer}`;
}
