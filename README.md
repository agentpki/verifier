# `@agentpki/verifier` — reference verifier

Cloudflare Worker implementation of the AgentPKI verification endpoint
(spec §8). Stateless, sub-50 ms p99, runs at the edge globally.

- **Spec:** https://agentpki.dev/spec/v0.1
- **Hosted instance:** `https://verify.agentpki.dev` (or the equivalent `*.workers.dev` URL until the custom domain attaches)

## What it does

Exposes a single primary endpoint:

```
POST /v1/verify
Content-Type: application/json
```

Implements the 12-step verification procedure of spec §8.2:

1. Parse the PASETO v4.public token
2. Extract `iss` and `footer.kid`
3. Resolve the issuer directory (cached in-isolate, 5-min TTL)
4. Select the appropriate public key by `kid`
5. Verify the Ed25519 signature
6. Check `exp`, `nbf`, version
7. Check `aud` against the relying site (if provided)
8. Check revocation list (stub in v0.1 — see roadmap)
9. If Mode B: verify the RFC 9421 HTTP Message Signature
10. Apply optional site policy (min_tier, required_scopes, max_abuse_score, require_signed)
11. Compute verdict (`allow` / `throttle` / `deny` / `unknown`)
12. Return the structured verdict with timings

See [`src/verify.ts`](./src/verify.ts) for the implementation.

## Quickstart

```bash
git clone https://github.com/agentpki/verifier
cd verifier
pnpm install
pnpm dev               # local development with miniflare
pnpm run release       # deploy to your own Cloudflare account
```

## Try the hosted instance

```bash
# Health check
curl https://verify.agentpki.dev/health
# {"ok":true,"ts":1779379420}

# Verify a passport (mint one first via demo.agentpki.dev/mint)
curl -X POST https://verify.agentpki.dev/v1/verify \
  -H 'content-type: application/json' \
  -d '{"token":"v4.public.eyJ..."}'
```

## End-to-end with the demo issuer

```bash
# 1. Mint a passport
TOKEN=$(curl -s 'https://demo.agentpki.dev/mint?sub=agent:hello/world' | jq -r .token)

# 2. Verify it
curl -s -X POST https://verify.agentpki.dev/v1/verify \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | jq
```

## Roadmap (v0.2+)

- [ ] Workers KV-backed issuer directory cache (cross-isolate persistence)
- [ ] Bloom-filter CRL distribution per spec §10.3
- [ ] Replay-detection cache (Durable Object) for Mode B
- [ ] Abuse-score aggregation (currently returns 0.0 placeholder)
- [ ] D1-backed audit log
- [ ] Workers Analytics Engine for verification metrics

## License

MIT. Spec it implements is Apache 2.0.
