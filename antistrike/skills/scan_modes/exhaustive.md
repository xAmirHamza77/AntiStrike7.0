# Exhaustive Scan Mode

Full-spectrum assessment covering every attack class in the Antistrike module registry.

## Phases
1. **Recon** — Subdomain enum, tech fingerprint, OSINT
2. **Discovery** — Port scan, directory brute, parameter discovery
3. **Vulnerability** — All injection, access control, and server-side tests
4. **API** — GraphQL, REST, JWT, OAuth, WebSocket
5. **Infrastructure** — Headers, TLS, CORS, cache behavior
6. **Chaining** — Correlate findings for multi-step attack paths

## Duration
Expect 2-8 hours depending on target complexity.

## Rules
- No DoS unless explicitly authorized
- Rate-limit requests to avoid service disruption
- Document every finding with reproducible PoC