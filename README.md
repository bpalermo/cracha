# Crachá

Crachá issues AWS credentials to Kubernetes workloads from their SPIFFE
identity: a few IAM roles per account, one per permission shape, with
per-workload session policies, attribution and revocation decided by a broker.

[docs/design.md](docs/design.md) is the design. The code is at the skeleton
stage.

## Build

```bash
bazel test //...
```

See [AGENTS.md](AGENTS.md) for the build, layout and conventions.
