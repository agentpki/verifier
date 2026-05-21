// Per-isolate in-memory cache for issuer directory documents.
//
// Cloudflare Workers reuse the same global module scope across requests within
// an isolate (with no guarantees, but typically minutes-to-hours of warmth).
// For v0.1 this gives us "free" caching without provisioning KV.
//
// v0.2 will swap to Workers KV with TTLs derived from Cache-Control headers
// per spec §6.3.

import type { IssuerDirectory } from '@agentpki/sdk';

interface CacheEntry {
  doc: IssuerDirectory;
  fetchedAt: number;
  expiresAt: number;
}

const TTL_SECONDS = 300; // 5 min default — matches spec §6.1 Cache-Control hint

const cache = new Map<string, CacheEntry>();

export function getCachedDirectory(issuer: string): IssuerDirectory | null {
  const entry = cache.get(issuer);
  if (!entry) return null;
  if (entry.expiresAt < Math.floor(Date.now() / 1000)) {
    cache.delete(issuer);
    return null;
  }
  return entry.doc;
}

export function setCachedDirectory(issuer: string, doc: IssuerDirectory, ttlSeconds: number = TTL_SECONDS): void {
  const now = Math.floor(Date.now() / 1000);
  cache.set(issuer, { doc, fetchedAt: now, expiresAt: now + ttlSeconds });
}

export function cacheStats(): { size: number; issuers: string[] } {
  return { size: cache.size, issuers: [...cache.keys()] };
}
