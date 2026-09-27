# Optional eBPF enforcement/observability

Derviq cannot transparently intercept arbitrary programs at kernel level from a portable Python service.

This directory is intentionally separated so a Linux deployment can add an eBPF program that observes/filters approved process/network identities and sends events to a Derviq agent.

Production requirements:
- Linux kernel with required eBPF features
- libbpf/bpf2go or equivalent build pipeline
- signed BPF objects
- capability/LSM policy review
- kernel compatibility testing
- explicit process/container identity mapping

The HTTP enforcement proxy in `app/proxy.py` is the immediately runnable enforcement surface. It only controls traffic deliberately routed through it and fails closed for non-allowlisted destinations.
