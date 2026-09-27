# Derviq — 12-Core Agent Control & Trust Engine

This build preserves the working control-plane engine and exposes the locked 12-core capability surface.

## Locked 12 Core Features
1. Cross-Vendor Agent Identity Registry
2. Hierarchical Agent Delegation Graph
3. Dynamic Context-Aware Risk & Policy Engine
4. Agent Spend & Resource Guardrails
5. Management-by-Exception Escalation
6. Degraded Execution & Hard Kill Switch
7. Shadow-Agent & Tool Discovery Scanner
8. Cryptographic Proof-of-Execution Graph
9. Cross-Vendor Non-Repudiation Vault (evidence layer)
10. Agent Intent & Authority Verification
11. Transaction Reversal & State Recovery (compensating-action boundary)
12. Cross-Organization Agent Dispute Resolution

Foundational rule: **Cross-Vendor Neutrality** — vendor/framework agnostic control plane.

## Security / Runtime
- PostgreSQL via SQLAlchemy; SQLite is suitable for local smoke tests.
- Tenant-scoped X-API-Key authentication with hashed keys.
- Rate limiting and request/body limits.
- Fail-closed upstream allowlist and private-network/SSRF blocking.
- Controlled HTTP forwarding and compensating recovery execution.
- SHA-256 chained evidence with HMAC-SHA256 integrity verification.
- Protected Swagger/OpenAPI endpoints.
- Docker/Render deployment structure using port 8080.

## Local smoke test
Set a local test database and run:

```bash
export DATABASE_URL=sqlite:///./derviq_smoke.db
export API_KEYS=smoke:smoke-secret
export API_SECRET_KEY=replace-with-a-long-random-secret
export REQUIRE_AUTH=true
pytest -q tests
```

The included test suite exercises the 12-core API surface plus authentication, tenant isolation boundaries, protected docs, and SSRF fail-closed behavior.

## Production configuration
Do not commit real `.env` files or secrets. Put real values in the deployment provider's secret/environment-variable store.

Required:
- `DATABASE_URL`
- `API_KEYS`
- `API_SECRET_KEY`

Optional:
- `PROXY_UPSTREAM_ALLOWLIST`
- `RATE_LIMIT_PER_MINUTE`
- `MAX_ACTION_BODY_BYTES`
- `FAIL_CLOSED`

The engine does not pretend that arbitrary vendor rollback, KMS/WORM storage, eBPF enforcement, payment settlement, or independent security certification exists without the corresponding external infrastructure and verification.
