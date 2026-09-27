# Derviq Control Plane — Ready-to-Run Core

This package provides a real FastAPI/PostgreSQL control plane with tenant-scoped API-key authentication, agent identity, delegation, policy evaluation, kill/degrade controls, cryptographic evidence-chain verification, rate limiting, allowlisted dynamic HTTP proxying, and real HTTP compensating recovery requests.

## Render
Set `PORT=8080` and `DATABASE_URL` to the Render PostgreSQL Internal Database URL. For production set `REQUIRE_AUTH=true`, `API_KEYS=tenant1:<long-secret>`, and configure `PROXY_UPSTREAM_ALLOWLIST`.

## Important scope boundary
A universal rollback of arbitrary third-party systems is impossible without target-specific compensation semantics. `/recovery` therefore executes a real, explicitly supplied compensating HTTP transaction against an allowlisted target; it does not pretend that arbitrary state can be magically rolled back. Likewise, KMS/WORM/eBPF require their respective external infrastructure and are not falsely marked as active by this package.
