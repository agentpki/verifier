// Build a fetch that routes known-internal issuers through a service binding.
//
// Why: Cloudflare short-circuits same-zone Worker-to-Worker fetches around
// the receiving Worker's route. When THIS Worker (on verify.agentpki.dev)
// does fetch('https://agentpki.dev/.well-known/agentpki-issuer.json'),
// the request hits Pages directly instead of the agentpki-self-issuer
// Worker that owns that route — so we get HTML back, not JSON.
//
// The fix: for any host we know we operate (currently just agentpki.dev),
// call the service binding's fetch() directly. External issuers still go
// through globalThis.fetch which works fine.

const INTERNAL_HOSTS: ReadonlySet<string> = new Set([
  'agentpki.dev',
]);

export function makeInternalFetch(env: { SELF_ISSUER?: Fetcher }): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    let host: string | null = null;
    try {
      const href =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      host = new URL(href).host;
    } catch {
      // unparseable input — let global fetch reject it
    }
    if (host && env.SELF_ISSUER && INTERNAL_HOSTS.has(host)) {
      return env.SELF_ISSUER.fetch(input as RequestInfo, init);
    }
    return globalThis.fetch(input, init);
  }) as typeof fetch;
}
