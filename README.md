# Derviq — Production-Oriented Agent Control & Trust Engine

This repository is a production-oriented rebuild of Derviq's 12-feature control plane.

## Important boundary

The code contains **real integration paths**, not fake success responses:
- PostgreSQL persistence
- JWT/OIDC-style authentication
- Microsoft Entra token/JWKS validation hooks
- AWS IAM/STS identity and policy evaluation hooks
- Google Cloud IAM/service-account integration hooks
- AWS KMS / Azure Key Vault / Google Cloud KMS signing adapters
- S3 Object Lock / Azure immutable blob / GCS retention adapters
- Agent HTTP enforcement proxy
- Fail-closed policy enforcement
- Cryptographic evidence DAG
- Recovery/dispute workflows
- Docker deployment
- Optional Linux eBPF observability starter

External integrations require real credentials, permissions, endpoints and infrastructure. If they are not configured, Derviq **fails closed or reports NOT_CONFIGURED**; it never pretends that an integration succeeded.

### Live financial settlement

No code path in this repository silently moves real money. Real bank/payment settlement requires an authorized merchant/account, provider credentials, transaction identifiers, legal controls and explicit deployment configuration. The repository exposes a provider-neutral settlement interface and reconciliation hooks rather than claiming fake "live money" functionality.

## 12 core features

1. Cross-Vendor Agent Identity Registry
2. Hierarchical Agent Delegation Graph
3. Dynamic Context-Aware Risk & Policy Engine
4. Agent Spend & Resource Guardrails
5. Management-by-Exception Escalation
6. Degraded Execution & Hard Kill Switch
7. Shadow-Agent & Tool Discovery Scanner
8. Cryptographic Proof-of-Execution Graph
9. Cross-Vendor Non-Repudiation Vault
10. Agent Intent & Authority Verification
11. Transaction Reversal & State Recovery
12. Cross-Organization Agent Dispute Resolution

Cross-vendor neutrality is a foundational rule.

## Run

```bash
cp .env.example .env
docker compose up --build
```

API:
- http://localhost:8080/health
- http://localhost:8080/docs
- http://localhost:8080/

PostgreSQL is used instead of the old in-memory store.

## Production checklist

Before production:
- put secrets in a secret manager, not `.env`
- configure OIDC issuer/audience and JWKS
- configure PostgreSQL TLS and backups
- configure one immutable evidence backend
- configure KMS/Key Vault signing key
- configure actual Entra/AWS/GCP permissions
- place the enforcement proxy on the agent's network path
- deploy with least privilege
- run independent security review and penetration testing
- configure monitoring, alerting and incident response
- obtain legal/compliance review for your deployment and customers

Derviq is not a substitute for cloud-provider authorization controls; it is a neutral control layer that can sit across them.
