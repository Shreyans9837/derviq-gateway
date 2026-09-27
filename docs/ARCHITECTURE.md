# Derviq architecture

Agent/runtime
  |
  v
Derviq enforcement proxy / future eBPF hooks
  |
  +--> Identity + delegation graph
  +--> Dynamic risk/policy engine
  +--> Spend/resource guardrails
  +--> Intent/authority check
  |
  +--> ALLOW / DENY / DEGRADED / HUMAN
  |
  +--> Evidence DAG
          |
          +--> KMS signature
          +--> immutable object storage
          +--> recovery/dispute workflows

Cloud-native controls remain authoritative at each provider. Derviq adds a neutral cross-vendor decision/evidence layer.
