# What is real in this build

## Real and runnable
- FastAPI API
- PostgreSQL persistence
- agent/delegation/policy/recovery/dispute records
- hash-linked evidence chain and verification
- fail-closed HTTP enforcement proxy
- JWT validation when configured
- AWS STS integration status
- Azure DefaultAzureCredential integration status
- Google Application Default Credentials integration status
- AWS KMS signing adapter
- Azure Key Vault signing adapter
- Google Cloud KMS signing adapter
- S3 Object Lock write adapter
- GCS retention adapter
- web UI connected to the API
- Docker packaging

## Requires deployment configuration
- Entra tenant/application/JWKS
- AWS IAM role/policies
- GCP IAM/service account
- KMS keys
- immutable storage
- real network placement of proxy
- production database TLS/backups
- observability and secrets management

## Not falsely claimed as complete
- universal interception of arbitrary agents
- production eBPF enforcement
- live bank settlement
- universal automatic rollback across third-party systems
- automatic cross-company arbitration
- independent security certification

Those depend on external systems, contracts, credentials, deployment topology and provider-specific APIs.
