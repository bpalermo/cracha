# Crachá

Crachá issues AWS credentials to Kubernetes workloads from their SPIFFE
identity: a few IAM roles per account, one per permission shape, with
per-workload session policies, attribution and revocation decided by a broker.
A node agent serves the credentials to each pod over loopback, inside the
pod's network namespace, so a workload trusts nothing, mounts nothing and
never holds its own SVID.

[docs/design.md](docs/design.md) is the design. The code is at the skeleton
stage.

## Build

```bash
bazel test //...
```

See [AGENTS.md](AGENTS.md) for the build, layout and conventions.
