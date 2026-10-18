# AGENTS.md

Guidance for agents working in this repository.

## What this is

Crachá issues AWS credentials to Kubernetes workloads from their SPIFFE
identity. Four binaries with images: the credential broker (`broker`), the
node agent that serves each pod's credentials over a loopback listener bound
inside the pod's network namespace (`agent`), the mutating webhook that wires
pods up (`webhook`), and, on an install whose authorization store is SpiceDB,
the only writer of its relationships (`access`, design 6.9). [docs/design.md](docs/design.md)
is the design; read it before changing behaviour, and update it in the same
pull request when behaviour changes. Its invariants (section 11) must hold in
every change.

## Build and test

```bash
bazel test //...            # builds and runs the unit tests
bazel run //:gazelle        # after adding, removing or renaming any .go file
bazel run //:format         # format Starlark, Go and shell; CI runs //:format.check
bazel mod tidy              # after changing go.mod or a bazel_dep
bazel build --config=ci //...   # what CI builds: lockfile must be current, shellcheck on
```

### End to end

```bash
e2e/run.sh                      # the whole system in a kind cluster
E2E_AUTHZ=spicedb e2e/run.sh    # with SpiceDB as the authorization backend
E2E_ENROL=cni e2e/run.sh        # enrolling pods through the CNI plugin, not the init container
E2E_FILTER=TestName e2e/run.sh  # only the tests whose name matches
E2E_KEEP_CLUSTER=1 e2e/run.sh   # leave the cluster up to look around
E2E_CHART=0.1.0 e2e/run.sh      # a published chart and its images, not the checkout's
```

Needs docker, kind and kubectl; helm comes from Bazel. The suite in `e2e/` is
tagged `e2e` and excluded from `bazel test //...`; `e2e/run.sh` creates or
reuses the kind cluster `cracha-e2e`, loads the images built from the
checkout (the broker, the agent, the webhook and the suite's own two,
`e2e/client` and `e2e/stsstub`), deploys SPIRE (`e2e/spire.sh`: the server
and agent of `e2e/spire.yaml`, with the agent's Broker API open to
`cracha-agent` alone, and the entries of the three components and the test
workloads, the webhook's with its Service name as a DNS SAN), installs the
chart built from the checkout with `e2e/values.yaml` (the published
assignments, a short bundle poll, the SPIRE socket paths, the kind node's
CRI socket and netns directory, the STS endpoint), `e2e/values-local.yaml`
(the images just loaded) and a values file it writes for the version it
compiled from `e2e/grants` (the bundle and the assignments), signed with a
throwaway key and published into a ConfigMap, whose volume also lays out
an optional second version a test republishes under,
deploys the STS stand-in (`e2e/manifests/stsstub.yaml`, `e2e/stsstub`) and
runs the tests against the ambient kubeconfig. Nothing is generated or
handed to a workload: every certificate is an X.509-SVID from that SPIRE,
the agent reaches the broker over SPIFFE mTLS, and the test workloads see
only the loopback listener in their own network namespace, so there is no
CA anywhere in the suite. `E2E_AUTHZ` picks the broker's authorization
backend: `static` (the default) reads the assignments published with the
bundle, and a test republishes a changed copy of the tree (grantc from the
runfiles, the key from `E2E_BUNDLE_KEY`) and watches the running broker
take it; `spicedb` installs the chart with `e2e/values-spicedb.yaml` on
top, which deploys the chart's SpiceDB (memory datastore, one replica)
behind its SPIFFE gateway with a preshared key the script makes, has the
SPIRE server mint X.509-SVIDs for the identities the suite plays (broker,
access, reconciler and one the gateway does not know; `spire-server x509
mint`, handed to the tests as `E2E_SPICEDB_SVIDS`) and runs
`cracha-reconciler schema` built from the checkout on the host through a
`kubectl port-forward` to the gateway; the suite writes its relationships
(`e2e/spicedb_access_test.go`, the relationships `e2e/grants` gives the
static mode) as the access identity, and checks the gateway's method table
identity by identity. `E2E_ENROL` picks how the agent enrols a
pod (design 7.2): `init` (the default, the chart's) has the webhook inject
the `cracha-enrol` init container; `cni` installs the chart with
`e2e/values-cni.yaml` on top, which switches the agent to the `cracha-cni`
plugin. A kept cluster switches modes through the chart: the agent going
retires the plugin from the node (its `preStop` hook, design 7.2), and the
suite's cni leg checks that switch both ways with `helm upgrade`, through
the helm and chart package run.sh hands it as `E2E_HELM` and
`E2E_CHART_PACKAGE`. The tests that
need SpiceDB (revocation through Watch, suspension,
the cache's mode, the gateway) skip in static mode, those that look at one enrolment
mode's wiring skip in the other; the rest run everywhere, and one of them
checks that the static document and the grant tree assign the same
things. `e2e/client` is the workload: the AWS SDK with the injected
environment and nothing else, its first action the credential fetch with
the provider's retries off, reporting the answer, the request count and
then `GET /v1/grants` as JSON lines the tests read from its log, and
fetching again at `E2E_FETCH_INTERVAL` when asked. CI runs the script once
per backend and enrolment mode. The cluster is created from the node image
in `e2e/kind-node-image`, by tag and digest; CI's `e2e` job gives
`helm/kind-action` the same file and pins the kind release it is the
default of. To move to another Kubernetes, write the image for that minor
from the kind release notes into the file and the kind release into
`ci.yml` and `e2e-published.yml`; a kept cluster made from the old image is
reused as is until it is deleted.
`E2E_CHART=<version>` runs the suite against a published chart instead of
the one built from the checkout: run.sh pulls
`oci://$(bazel/registry.sh chart-ref cracha)` at that version with the
pinned helm, installs it with the images it pins (the node pulls them from
the registry; the checkout's broker, agent and webhook images are neither
built nor loaded and `values-local.yaml` is not passed) and prints the
chart's digest and its image pins first, so the log says what was tested.
The suite, SPIRE, the bundle, the STS stand-in and the suite's own images
still come from the checkout, so run it from the commit whose suite
matches the chart. The `e2e-published` workflow
(`.github/workflows/e2e-published.yml`, run by hand with the chart version,
the backend and the enrolment mode) does the same in a kind cluster on a
runner. Every change that adds user-visible behaviour extends the suite,
and a change to how Crachá is deployed goes in the chart, not in a
manifest.

Bazel is the only build. Never run the host `go` tool: not `go mod tidy`, not
`go get`, not `go test`. Change a Go dependency through rules_go's SDK:

```bash
bazel run @rules_go//go -- get github.com/some/module@v1.2.3
```

Follow it with `bazel mod tidy` and `bazel run //:gazelle`. Go modules are
fetched directly from their repositories in the user's Go environment
(`GOPROXY=direct`); the untracked `user.bazelrc` points Bazel's own fetches at
the public proxy instead.

Linting is part of the build. Every Go package is compiled with the analyzers
of `//:nogo` (`go vet`'s and staticcheck's), and a finding is a compile error:
fix it rather than excluding the file. Go functions are also held under a
cognitive-complexity ceiling of 15 by gocognit (`bazel/lint/linters.bzl`;
never raise it). Shell
scripts are checked by shellcheck, an aspect that `--config=ci` turns on; a script is only seen through a Bazel
target, so a new directory of scripts needs an `sh_library` like
`//bazel:scripts`.

CI runs with `--config=ci`, which fails if `MODULE.bazel.lock` is out of date,
and requires that Gazelle leaves no diff. Regenerate BUILD files rather than
hand-editing what Gazelle owns.

### What CI runs for a change

CI builds and tests only what a change impacts. The `diff` job hashes the
build graph at the base and the head of the change with bazel-diff
(`bazel/ci-impacted-targets.sh`) and hands `build` the impacted rules to
build and the impacted tests to run; `build` is skipped when nothing is
impacted, and the `e2e (kind, <authz>, <enrol>)` matrix, one leg per
authorization backend and enrolment mode (`E2E_AUTHZ`, `E2E_ENROL`), runs
only when the impacted set reaches something the suite deploys or runs:
anything under `//e2e/...`, the chart `//charts/cracha:cracha` or a
component's `image_load`. The suite's manifests, values files, `spire.sh`
and `run.sh` are `data` of `//e2e:e2e_test`, so editing one of them is an
e2e-relevant change; a new fixture the suite deploys goes in that glob. The
`ci` aggregate takes the matrix as one result: every leg has to pass. A documentation-only change
builds nothing and creates no kind cluster; the formatter and the Gazelle
check run on every change regardless. A change to the files CI itself
depends on and no target does (`.bazelrc`, `.bazelversion`, `MODULE.bazel`
and its lock, `ci.yml`, the script, the lint aspects under `bazel/lint/` and
`.shellcheckrc`, which `.bazelrc` attaches to every build) runs everything, as does
any error in the computation: the fallback is always a full run, never a
smaller one. To see what a change would run, from a clone (the script checks
revisions out, so not the checkout you are working in) with bazel-diff from
its GitHub release at the version `ci.yml` pins:

```bash
BASE_SHA=origin/main BAZEL_DIFF=~/bin/bazel-diff bazel/ci-impacted-targets.sh
```

The decision after bazel-diff is covered by `//bazel:ci_impacted_targets_test`.

## Layout

- No `cmd/`. Each binary lives in a root-level directory with its `main.go`:
  `broker/`, `agent/`, `webhook/`, `access/`, `grantc/`, `reconciler/`.
- `agent/` is `cracha-agent` (design 7). `internal/listener` is the registry
  of loopback listeners, one per enrolled pod, bound inside the pod's network
  namespace by `internal/netns` (setns on a dedicated locked thread) and
  multiplexed into one `http.Server`; the pod a request is answered for is
  the listener it arrived on, nothing in the request. `internal/credentials`
  is the endpoint (`GET /v1/credentials` and `/v1/grants`): the pod's
  JWT-SVID through the issuer adapter (`internal/issuer`, SPIRE's Broker API
  in `internal/issuer/spire`), cached in memory until a minute before expiry,
  then the broker's answer relayed unchanged over SPIFFE mTLS
  (`internal/broker`, the agent's own SVID from `internal/identity`, the
  broker verified by SPIFFE ID). Enrolment (design 7.2) is `internal/enrol`:
  the label check and bind both modes share, the init-mode endpoint
  (`POST /v1/enrol`, TokenReview of the init container's bound token in
  `internal/tokenreview`, the sandbox's namespace path through the CRI in
  `internal/cri`) and the `cracha-agent enrol` client; cni mode's server side
  is `internal/cni/server`, speaking `agent/cni/proto` (JSON over HTTP on a
  Unix socket the agent creates 0600 in a 0700 directory). `internal/recovery`
  rebinds the node's enrolled pods on start from a filtered pod informer and
  closes the listeners of pods that go. `agent/enrolapi` is the contract the
  webhook imports: the enrolment label, the endpoint, the init container's
  environment.
- `agent/cni` is `cracha-cni`, the chained CNI plugin of cni mode (design
  7.2), built from the agent's tree: `main.go` over `internal/plugin`
  (ADD tells the agent the pod and its netns path and prints the previous
  plugin's result byte for byte, failing closed when the agent is down or
  refuses; DEL is best effort; CHECK, GC and STATUS do nothing) and
  `netconf`, the conflist entry both the plugin and the installer import.
  It has no image of its own: `//agent:image` carries it at
  `/opt/cracha/cni/cracha-cni`, and `cracha-agent cni-install`
  (`agent/internal/cni/install`, the DaemonSet's init container in cni
  mode) copies it into the node's CNI bin directory and chains it after
  the primary plugin of the lexically first conflist of the CNI conf
  directory, with write-fsync-rename and nothing rewritten when already
  there (`--uninstall` undoes it). `cracha-agent cni-retire`
  (`agent/internal/cni/retire`, the agent container's `preStop` hook in
  cni mode) runs that uninstall when the agent is not coming back in cni
  mode: its DaemonSet gone or being deleted, the DaemonSet's pod template
  annotation `cracha.dev/enrol` no longer `cni`, or its token refused
  (401) for the whole budget; on anything else it logs and leaves the
  plugin. `go_image` takes the extra file through its `files` argument.
- Code private to a binary goes under its `internal/`. The webhook's
  `internal/mutate` is the admission decision (design 7.5), pure over two
  interfaces: ServiceAccount lookups (`internal/sacache`, a Get remembered
  for a TTL) and the per-namespace `AWS_REGION` override
  (`internal/nsregion`, the `cracha.dev/region` Namespace annotation served
  from an informer; the chart's ClusterRole lists and watches namespaces
  for it). It injects the loopback `AWS_CONTAINER_CREDENTIALS_FULL_URI`
  (`--agent-port`), `AWS_REGION`, the label `cracha.dev/credentials` (the
  idempotency key) and, with `--enrol=init`, the `cracha-enrol` init
  container from `--agent-image` with its projected token (audience
  `cracha-agent`, at `mutate.EnrolTokenPath`, also in
  `CRACHA_ENROL_TOKEN_FILE`; `CRACHA_HOST_IP`, `CRACHA_ENROL_PORT`,
  `CRACHA_AGENT_PORT`, `CRACHA_ENROL_TIMEOUT`; every name is
  `agent/enrolapi`'s, the one definition of the contract) with the
  resources of `--enrol-cpu` and `--enrol-memory` as its requests and
  limits alike (defaults `mutate.DefaultEnrolCPU`, 100m, and 32Mi: under
  about 100m runc's init and the enrol binary are CFS-throttled and a pod
  sits in Init for tens of seconds, which the e2e's first-fetch test
  bounds at 5 s); the golden
  pods of each mode are
  `internal/mutate/testdata/*.golden.json` (refresh with
  `--test_env=UPDATE_GOLDEN=1`). `internal/server` serves HTTPS with the
  `*tls.Config` it is given, which `main.go` builds from the webhook's
  X.509-SVID (`--workload-api-socket`), and drains when told to stop
  (readiness false, then `--drain` of answering with `Connection: close`,
  then the shutdown; `main.go` keeps the informers and the Workload API
  source alive until the server has returned); `internal/cabundle` keeps the
  `caBundle` of the chart's `MutatingWebhookConfiguration`
  (`--webhook-config-name`) at the trust bundle of the webhook's trust
  domain, on start, on every Workload API update and on a resync.
- Code shared between binaries goes under `common/`. `common/idenc` is the
  single identity-encoding library (design 4.3): nothing else formats a
  SourceIdentity, an authorization subject ID or a resource's object ID
  (`idenc.Resource`, the escaped resource name of Level 3).
- `common/grant` is the grant bundle model and compiler (design 6.2): loading,
  validation, templates, lints, the compiled bundle and assignments,
  signing (one key or a `KeyRing` of several) and publishing. Who holds
  what is `ResolveAssignments` and `ResolveAccess`, the one mapping from
  Services, Assignments and Access documents that the published
  assignments document comes from.
  Its source tree holds five kinds: `Account` (an AWS account's account
  role, the default envelope of its grants and its access table, whose
  entries compile into implicit lookup grants named
  `account:<name>:<kind>:<permission>`, `account.go`), `Grant` (whose
  `baseRole` and `envelope` default to its Account's; `baseRole` is the
  dedicated-shape override), `Assignment` (a workload's own
  grants, optionally bounded, or its `suspended: true`), `Service` (a
  team's workloads and the grants they share, each bounded like an
  Assignment; a workload is a member of at most one service) and `Access`
  (a workload's or a service's members' `reader` or `writer` relation to
  one resource, an `s3_bucket` or a `dynamodb_table`, bounded the same
  way). A grant may leave one template parameter to a lookup (Level 3):
  the bundle then carries the template and the compiled maximum of
  resources (`lookup.go`, `resource.go`), the broker renders it at
  issuance with `Template.RenderLookup`, the compiler's own rendering. The
  composition lint unions a subject's grants from both and the implicit
  grants its Access brings in, its lookup grants rendered with its Access,
  and refuses a union of two accounts or two roles. Everything after
  validation reads `Source.CompiledGrants`, the grants with their
  account's defaults applied and the implicit ones, never `Source.Grants`.
  A tree without Account documents must compile to the bytes and version
  it did before them (`compat_test.go`). Names are DNS labels without dots, because
  they become SpiceDB object IDs; resource names may hold dots, so they go
  through `idenc.Resource`.
- `common/spicedb` is the SpiceDB schema (design 6.4), embedded from
  `schema.zed`, and the constants for every object type, relation,
  permission, caveat and caveat context key in it: the broker's adapter,
  the access service and the reconciler spell nothing in the schema twice.
  `common/spicedb/conn` is how every client dials SpiceDB: SPIFFE mTLS to
  the gateway with its own X.509-SVID, the gateway verified by SPIFFE ID,
  no preshared key. `common/spiffetest` mints test SVIDs.
- `grantc/` is the grant compiler CLI over `common/grant` (lint, compile,
  sign, verify, publish); it runs in CI and has no container image. The
  grants themselves are not in this repository: they live in the private
  `bpalermo/cracha-grants`, whose CI calls the reusable
  `.github/workflows/grants.yml` with a released, verified `grantc`
  ([docs/grants-repository.md](docs/grants-repository.md)). Never commit a
  grant tree or a caller of that workflow here.
- The broker's authorization store is one of two backends, chosen by
  `--authz-backend`: `static` (`broker/internal/authz/static`, with
  `--assignments-source file`, the default, the file `--assignments` read
  once, or with `published` the assignments of the version the bundle
  source serves, swapped with its bundle; its Watch reports every swap as
  a change of every subject) or `spicedb`
  (`broker/internal/authz/spicedb`, the adapter over the reference model of
  design 6.4: it dials the gateway with its own SVID
  (`--spicedb-endpoint`, `--spicedb-server-spiffe-id`) and holds no key;
  the gateway admits it to reads only; every query carries the caveat context `now` and `cluster`;
  every error is a deny; its Watch feeds the cache). The contract both
  answer is `broker/internal/authz`, `LookupResources` included, and the
  SpiceDB tests hold the adapter to the static backend's answers for the
  same assignments and access.
- `reconciler/` is `cracha-reconciler`, which writes the SpiceDB schema
  (design 6.4) through the gateway with an SVID from the Workload API
  (`-workload-api`) or from files (`-svid`, `-svid-key`, `-bundle`), and
  reads it back. It writes no relationship: with the spicedb backend they
  live only in SpiceDB and the access service is their one writer; `apply`
  refuses with that message. Like `grantc` it runs from CI or an
  operator's machine and has no container image; the e2e runs it from the
  host through a port-forward to the gateway.
- The broker's transport is `broker/internal/mtls` (design 6.5): the TLS
  configuration over go-spiffe (`tlsconfig.MTLSServerConfig`, the agent's
  ID the only one authorised, so any other client fails at the handshake),
  the peer identity of a request, which `broker/internal/api` logs beside
  the token's subject with every request, and the readiness check that
  waits for the broker's SVID. `broker/spiffe.go` is the broker's one
  Workload API connection, which the X.509 source (mTLS) and the JWT
  source (token verification) share. The probes are `broker/internal/health`,
  on their own plaintext listener (`--health-listen`); the API listener
  serves nothing but `/v1/credentials` and `/v1/grants`. `mtls/mtlstest`
  mints the X.509-SVIDs the tests use, as `authn/authntest` mints JWTs.
- The broker gets its grants from one of two sources, exactly one of which
  is configured. In production it is the compiled bundle `grantc` publishes
  (`--bundle-source local:<dir>` or `s3://bucket/prefix`,
  `broker/internal/bundle`): polled, its signature verified over the
  published bytes with public keys (`--bundle-verify-key`, repeatable, each
  file one or more PEM keys, any of which verifies: rotation is adding the
  new key's PEM beside the old one) or a KMS key's public key
  (`--bundle-kms-key`, fetched once with `kms:GetPublicKey`), swapped
  atomically when the version changes, and
  kept at the last good version on any failure; `/readyz` reports not
  ready until a bundle has verified. With `--assignments-source published`
  every version's assignments are fetched and verified too, and the
  version goes in service only with both: the pair swaps together, and is
  kept together on any failure of either. For development it is the
  resolved-grants fixture (`--grants-fixture`,
  `broker/internal/grants/fixture.go`), which the chart's default
  `broker.grants` renders; `broker.bundle` switches an install to the
  bundle. The e2e installs the bundle path. Only the bundle has accounts:
  `bundle.Source` is a `grants.ImplicitSource`, whose implicit grants
  `grants.Compose` applies by the workload's relations (one
  `LookupResources` per kind and permission) and never resolves by name;
  a composition of two accounts is `accounts_mixed`, and one with neither
  a session policy nor managed policies is refused, since on a shared
  account role it would be the role's whole policy.
- `access/` is `cracha-access` (design 6.9): `serve` is a gRPC API
  (`cracha.access.v1.Access`, JSON messages in gRPC frames, so no protoc:
  `internal/api`) over SPIFFE mTLS that any SPIFFE ID of the trust domain
  may call, `watch-audit` logs SpiceDB's Watch, and the other subcommands
  are its CLI, which calls it with the caller's SVID. `internal/store` is
  its SpiceDB adapter (relationships as `Tuple`s, `manage`/`approve`
  checks, the `sensitive` flag, pending requests as `pending_request`
  relationships, Watch); `internal/check` the safeguards, which rebuild
  the grant tree a write leaves from the bundle and SpiceDB's
  relationships and run `common/grant`'s `LintComposition` on it, refusing
  with the broker's reason codes; `internal/service` the write path
  (authorization, expiry, approvals, break-glass, audit);
  `internal/audit` the JSON audit lines on stdout. Its tests run against
  `internal/store/storetest`, an in-memory SpiceDB, and a bundle
  `internal/check/checktest` compiles with `common/grant`. It reads the
  bundle with `common/publication`, the fetchers the broker uses
  (`broker/internal/bundle` aliases them) and a verifying poller that
  keeps the last good version.
- `bazel/` holds build rules, and `bazel/spicedb` the third-party SpiceDB
  binary Crachá builds and publishes from its upstream module plus the
  patches beside it (below); `docs/` the design; `charts/cracha` the Helm
  chart; `e2e/` the end-to-end suite with its values files, the fixtures it
  deploys beside the chart and the two images only it uses.

## Images and versions

- The registry is named in one build file, `bazel/registry.bzl`. Nothing else
  may spell it out.
- Images are built with the `go_image` macro in `bazel/image/defs.bzl`, from
  pure-Go binaries on a digest-pinned distroless base. Image repositories are
  `broker`, `agent`, `webhook`, `access` and `spicedb`.
- `spicedb` (`//bazel/spicedb`) is a third-party binary: SpiceDB built
  from a pinned upstream release (`github.com/authzed/spicedb` in `go.mod`, a
  `tool`, so nothing imports it) plus one reviewed patch,
  `0001-mysql-client-tls.patch` (MySQL client TLS:
  `--datastore-tls-{ca,cert,key}-path`, `--datastore-tls-server-name`,
  reloaded on rotation). That patch is the only change Crachá makes to
  SpiceDB; `0002-bazel-build-files.patch` only adds the file it creates to the
  BUILD file Gazelle generated, since `go_deps.module_override` applies
  patches after Gazelle runs. The binary is built as upstream's release is
  (cgo off, the `memoryprotection` tag, `-checklinkname=0`) and `spicedb
  version` reports `SPICEDB_VERSION` of its BUILD file, the release with a
  `-cracha.<n>` suffix; `//bazel/spicedb:spicedb_test` checks the
  version against `go.mod`, the patch's flags, and a schema write and
  permission check against the binary. To bump SpiceDB: rebase Bruno's fork
  branch `mysql-client-tls-v<version>` of bpalermo/spicedb onto the new
  release; regenerate the patch with `git diff v<version>..mysql-client-tls-v<version>`
  over its non-test Go files; `bazel run @rules_go//go -- get
  github.com/authzed/spicedb@v<version>`, `bazel mod tidy`; refresh `0002`
  if Gazelle's BUILD file for the package changed; set `SPICEDB_VERSION` to
  `v<version>-cracha.1`; and report which shared modules Crachá's own
  requirements now hold above what that release's `go.mod` asks for. A change
  to the patch alone bumps the suffix.
- `VERSION` holds the release being worked towards. Binaries report the commit
  they were built from, stamped by `bazel/workspace_status.sh`.

## Chart

- `charts/cracha` is the Helm chart: the agent DaemonSet, the broker,
  the webhook and, with `access.enabled` (off by default; it needs
  `broker.authz.backend` spicedb and `broker.bundle.source`), cracha-access:
  one replica with the `Recreate` strategy, since it serializes the writes
  it checks, its ServiceAccount `<name>-access` (the SPIFFE ID the SpiceDB
  gateway lets write) and Service, reading the broker's bundle source and
  keys (`access_test.go` asserts its arguments). It is built, linted, templated and
  installed with the helm that rules_helm pins (`@helm//:helm`, the version
  in `MODULE.bazel` and `.bazelrc`); never a helm from PATH.
  `bazel build //charts/cracha:cracha` packages it as
  `bazel-bin/charts/cracha/cracha.tgz`; `bazel test //charts/cracha/...`
  runs the lint, template (defaults, every override) and pin
  tests, and the Go assertions over the rendered objects (`render_test.go`
  decodes the `helm_template` renderings of `BUILD.bazel`; an assertion
  on what a template renders goes there, since `helm_template_test` only
  renders).
- `agent.brokerAPI.group` gives the agent the Broker API socket's group as
  a supplementary group: SPIRE's socket is 0770, owned by the spire-agent's
  uid and gid (1000 with the SPIRE chart), and the agent is root without
  `CAP_DAC_OVERRIDE`. The e2e runs SPIRE's agent as 1000:1000 (run.sh owns
  the socket directories on the node to it first) so a missing group fails
  the suite (`TestAgentBrokerAPIGroup` covers the render).
- The agent DaemonSet tolerates no taint by default
  (`TestAgentTolerations`): it must run exactly where the identity issuer's
  agent does, since its hostPath mounts of the issuer's sockets fail
  anywhere else; an install mirrors the issuer agent's tolerations in
  `agent.tolerations`.
- The agent, the broker and the webhook have default resource requests and
  memory limits and no CPU limits (`TestDefaultResources`): a BestEffort pod
  on a busy node gets its probes starved and restarted, and a CPU limit
  throttles the short bursts these binaries have.
- The chart's version and image pins are stamped at package time: the
  version from `STABLE_CHART_VERSION`, each image's repository and digest
  from its `image_push` target (`{@//agent:image_push.digest}` in
  `values.yaml`). Do not write a version or a digest into `Chart.yaml.in` or
  `values.yaml` by hand; `//charts/cracha:pin_test` checks the result with
  `bazel/chart-pin.sh`.
- The agent's values are `agent.*` with the design's names: `port`,
  `enrol` (`init` or `cni`), `enrolPort`, `enrolTimeout`, `enrolResources`
  (`cpu` and `memory` of the `cracha-enrol` init container, passed to the
  webhook as `--enrol-cpu` and `--enrol-memory`), `fetchDeadline`,
  `brokerUrl`, `brokerSpiffeID` (empty: the broker ServiceAccount's path in
  the agent's own trust domain), `criSocket`, `netnsDir`, `cni.socket`,
  `cni.binDir`, `cni.confDir`. The DaemonSet is in the host network with
  `CAP_SYS_ADMIN` alone; its host mounts are the CRI socket, the runtime's
  netns directory (read-only, `HostToContainer`) and the issuer's sockets,
  and `agent_test.go` holds it to that. `agent.enrol: cni` renders the
  socket's hostPath for the agent container and the `cni-install` init
  container from the agent image, with `cni.binDir` and `cni.confDir`
  mounted read-write (no capability, read-only root): on the
  node it writes `<binDir>/cracha-cni` and rewrites the lexically first
  conflist of `confDir` (kind: `10-kindnet.conflist`) with the entry
  `{"type": "cracha-cni", "socket": <cni.socket>, "timeout": "5s"}`
  appended to its `plugins`, and touches nothing else. The agent container
  mounts the same two directories read-write in cni mode for one reason:
  its `preStop` hook, `cracha-agent cni-retire`, which takes the plugin
  off the node when the agent is not coming back in cni mode (the chart
  uninstalled, or `agent.enrol` switched: it reads its own DaemonSet,
  through the Role `get` on that one DaemonSet by name that both modes
  render, and compares the pod template's annotation `cracha.dev/enrol`,
  which the template always carries) and leaves it on a restart, a
  rollout or a drain; `terminationGracePeriodSeconds` is 60 in cni mode
  to cover the hook. A node that lost its agent pod without the hook (a
  crash) keeps the plugin: `cracha-agent cni-install --uninstall` once on
  the node, or the chart installed again in cni mode, fixes it.
  `test/agent-cni.yaml` renders cni mode with non-default directories and
  `agent_test.go` checks the installer, the hook, the mounts and the Role.
- `broker.authz.backend` picks the authorization store: `static` (the
  default) renders, with `broker.assignments.source` `file` (the default),
  the assignments ConfigMap and its mount, and with `published` neither
  (the broker reads them from `broker.bundle.source`, which it needs;
  `test/assignments-published.yaml` renders it, since the overrides render
  SpiceDB); `spicedb` takes `broker.authz.spicedb` (the gateway's
  `endpoint` and `serverSpiffeID`, both defaulting to the chart's own, and
  `timeout`) and renders `spicedb.*` unless `spicedb.enabled` is false:
  SpiceDB and the Envoy gateway in one pod (SpiceDB on the loopback, the
  key from `spicedb.presharedKeySecret`, mounted by that pod alone; Envoy
  the one listener, its SVID from the SPIRE agent's SDS, its RBAC the
  method table of design 6.4 generated from `spicedb.gateway`), the
  datastore (`memory`, `mysql`, `postgres`, the URI from a Secret, an
  optional CA and Postgres client certificate) and the migration Job.
  `spicedb_test.go` holds the RBAC to exactly the three identities with
  exactly their methods. The SpiceDB and Envoy images are pinned by hand,
  by tag and digest, in `values.yaml`, the only place either is spelled.
- Brokers verify the publication with the signing key's PEM and need no
  KMS access: a KMS signature's `keyId` is its public key's identity, the
  same a local verifier of the exported PEM computes (`aws kms
  get-public-key`, or the Terraform output, gives it), and nothing calls
  `kms:Verify`. Never commit a real key's ARN or PEM to this repository.
- `broker.bundle.verifyKey` is one PEM key, a string of several or a list
  of them, all in the one Secret file the broker reads, any of which
  verifies: a signing key rotates by trusting the new key beside the old,
  signing with the new, then dropping the old.
- `agent.prewarm` (default on) has the agent run a pod's first credential
  request in the background whenever it binds the pod's listener (design
  7.2), so the app's first request is a broker cache hit; the agent still
  keeps no credentials. `webhook.sdkTimeouts` sets the
  `AWS_METADATA_SERVICE_TIMEOUT` and `_NUM_ATTEMPTS` the webhook injects
  unless a container sets its own (design 7.5); of the first-party SDKs
  only PHP reads them for the container provider (the table in design
  7.7), so prewarm, not the variables, is what keeps the others inside
  their timeouts. The timeout is whole seconds: botocore parses it as an
  integer.
- `test/overrides.yaml` must exercise every non-default knob: a new value
  goes there too. A value every install must give (`broker.cluster`,
  `webhook.defaultRegion`) is `required` in the templates and listed in
  `test/required.yaml`.
- Helm merges an install's values into the defaults, so a volume source
  the defaults fill in (`broker.workloadAPI.volume`) is never rendered with
  `toYaml` of the whole map: an install choosing another source would get
  both. Such a value is a `type` naming the source beside one map per
  source, and a helper renders the chosen one only
  (`cracha.workloadAPIVolumeSource`). `//charts/cracha:cracha_test` fails
  any rendered volume with two sources, in every rendering it has.
- The broker has no certificate from the chart: it serves SPIFFE mTLS with
  its own X.509-SVID from the Workload API and admits one client, the node
  agent, by SPIFFE ID (design 6.5). `broker.agentSpiffeID` names it; empty,
  the default, leaves the broker to derive
  `spiffe://<its own trust domain>/ns/<its namespace>/sa/cracha-agent`, the
  namespace coming from `CRACHA_NAMESPACE`, which the Deployment sets from
  the downward API. The kubelet's probes cannot present an SVID, so
  `/healthz` and `/readyz` are served plaintext on `broker.healthPort`
  (`--health-listen`), a port that serves nothing else and is not on the
  Service.
- The webhook has no certificate from the chart either, so the chart has no
  TLS values at all: it serves its X.509-SVID from the Workload API
  (`webhook.workloadAPI`, the volume with its `type` and socket shaped as
  the broker's), and the `MutatingWebhookConfiguration`
  is rendered without a `caBundle`, which the webhook patches in itself (its
  ClusterRole has `get` and `patch` on that one object by `resourceNames`).
  The configuration's `namespaceSelector` excludes the release namespace
  and `webhook.excludedNamespaces` (a list that replaces the default of
  SPIRE's namespaces and `kube-system`), and, when
  `webhook.namespaceLabels` or `webhook.podLabels` is set, sees only pods
  whose namespace carries the namespace labels or which carry the pod
  labels (two webhook entries, `pods.cracha.dev` and
  `labelled-pods.cracha.dev`, since a webhook's selectors are ANDed): with
  `failurePolicy: Fail` an unreachable webhook refuses every pod it covers,
  so a cluster shared with other workloads installs it opt-in. The render
  fails on `cracha.dev/credentials` as a pod label, which the webhook sets
  itself; the e2e installs opt-in both ways (`TestWebhookOptIn`). The webhook reads the agent's
  values `agent.image`, `agent.port`, `agent.enrol` (`init` injects the
  `cracha-enrol` init container, `cni` nothing but env and label),
  `agent.enrolPort`, `agent.enrolTimeout` and `agent.enrolResources`;
  `render_test.go` asserts the
  configuration and the Deployment's arguments in both modes.
- The webhook's rollout loses no admission (design 7.5): `webhook.drain`
  (`--drain`, default `5s`) is how long a pod told to stop keeps
  answering, not ready, before it shuts down, and `webhook.shutdownTimeout`
  (`--shutdown-timeout`, `10s`) how long the shutdown then waits for the
  admissions in flight; the Deployment's `terminationGracePeriodSeconds`
  is the two plus 5 s of margin (`cracha.seconds` of `_helpers.tpl` turns
  the durations, whole seconds only, into the number), its strategy is
  `RollingUpdate` with `maxUnavailable: 0` and `maxSurge: 1`, and
  `webhook.minReadySeconds` (5) keeps the new pod Ready that long before
  the old one is told to stop. The binary drains; there is no `preStop`
  hook. The e2e's `TestWebhookRolloutLosesNoPod` restarts the Deployment
  and requires every create of the next 15 s to be admitted at the first
  attempt.
- The chart is published to `chart_registry_url("cracha")` of
  `bazel/registry.bzl` by the publish workflow (below).

## Publishing

- Every published coordinate comes from `bazel/registry.bzl`: the registry
  host, the organization, the four image repositories and the chart's.
  Bazel loads it; shell and the workflows read it through `bazel/registry.sh`
  (`bazel/registry.sh` prints `KEY=VALUE` lines, `bazel/registry.sh ref agent`
  one reference). `bazel/check-registry-config.sh`, run by the `lint` job of
  `ci.yml`, fails a change that spells the registry out anywhere else; the
  README is the one file allowed to, because people copy install commands
  from it. Moving registries is an edit to `bazel/registry.bzl` and nothing
  else.
- `.github/workflows/publish.yml` publishes on every push to `main` and on
  every `v*` tag, in the GitHub environment `release`, which only `main` and
  `v*` tags may use. It builds everything it will push in one
  `bazel build --config=ci` before any credential exists on the runner,
  refuses an unstamped chart or a chart whose pins are not the digests it is
  about to push, logs in to the registry once (`docker/login-action`, which
  `image_push` and cosign both read), pushes the four images, signs each
  index and its platform manifests keyless by digest with the pinned cosign
  (`cosign sign --recursive`), verifies them before signing (so an unchanged
  digest is not signed twice) and after, then pushes the chart with
  `//charts/cracha:cracha.push_registry` and signs and verifies it the same
  way. A `check` job pulls the chart back by its version with the pinned helm,
  asserts it is the manifest the push reported and pins the digests that were
  pushed, and verifies every signature without credentials. The workflow
  cannot be exercised from a pull request, so read a change to it twice and
  watch the run after merge. It reads files from `bazel-out`: an output that
  is not a target's default output is absent there on a cache hit, so request
  its output group in the build step (see `--output_groups=+digest`).
- The credentials are a Quay robot account of the `cracha` organization that
  can write (not create) the repositories, in the secrets `QUAY_USERNAME` and
  `QUAY_TOKEN` of the `release` environment; nothing else is configured
  outside the repository. The repositories are public, and they are created
  by hand: a new image needs its quay.io repository, an entry in
  `bazel/registry.sh` and the comments of `bazel/registry.bzl`, the build
  lists of `ci.yml` and `publish.yml` (build, push, record, sign, verify,
  check, release notes) and, if the chart deploys it, `values.yaml`, the
  chart's `images` and `PINNED_COMPONENTS`, and the chart loop of
  `bazel/check-registry-config.sh`, which fails an image a BUILD file
  publishes that `bazel/registry.sh` does not print.
- On a `v*` tag the `grantc` job of `publish.yml` builds
  `//grantc:grantc_{linux_amd64,linux_arm64,darwin_arm64}` (`go_cross_binary`
  of the pure-Go, stamped `//grantc`; `//grantc:release_binaries_test`
  checks each one's header and that the linux ones are static), names them
  `grantc_<version>_<os>_<arch>` (the version without its `v`), writes
  `checksums.txt` (sha256), signs it keyless with the pinned cosign
  (`cosign sign-blob`, the Sigstore bundle `checksums.txt.sigstore.json`)
  and verifies it; `release` attaches the five files to the GitHub Release.
  A snapshot of `main` publishes no binaries. A new platform is a name in
  the list of `grantc/BUILD.bazel`, in `GRANTC_PLATFORMS` of `publish.yml`,
  in the query of `ci.yml` and in the release job's expected files.
- `.github/workflows/grants.yml` is the reusable workflow
  (`on: workflow_call`) a grants repository runs: it verifies a release's
  `checksums.txt` signature against `publish.yml@refs/tags/<version>` and
  the binary against it, assumes the caller's role through GitHub OIDC and
  runs `grantc` (docs/grants-repository.md). It declares no environment,
  since one would change the OIDC subject the roles trust. It cannot run
  Bazel, so it downloads cosign itself, pinned by version and sha256.
- cosign is the release binary the `rules_img_signer_cosign` bazel_dep pins by
  sha256, wrapped as `//bazel/cosign`; `//bazel/cosign:version_test` fails
  when the pin and the test's `EXPECTED` disagree, so bump both together,
  and `//bazel/cosign:workflow_pin_test` fails when `COSIGN_VERSION` and
  the sha256 of `grants.yml` are not that cosign, so bump those with it. To
  verify a published image (the index and every platform manifest, and that
  the signature is a referrer as `SIGNATURE_LAYOUT` promises) or the chart:

  ```bash
  bazel run //bazel/cosign:verify_image -- "$(bazel/registry.sh ref agent)@sha256:<digest>"
  bazel run //bazel/cosign:verify_image -- --single "$(bazel/registry.sh chart-ref cracha)@sha256:<digest>"
  bazel run //bazel/cosign -- verify "$(bazel/registry.sh ref agent)@sha256:<digest>" \
    --certificate-identity-regexp '^https://github.com/bpalermo/cracha/.github/workflows/publish.yml@refs/(heads/main|tags/v.*)$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

### Releasing

- `VERSION` holds the release being worked towards. Every commit to `main`
  publishes a snapshot of it: the chart as `<VERSION>-dev.<commit time>.g<commit>`,
  the images under the mutable tag `dev` and the immutable `dev-<commit>`.
- A release is a tag `v<VERSION>` on a commit of `main`, pushed by a person.
  Cut a candidate first, `v<VERSION>-rc.<n>`, since the tag path of the
  workflow runs only on a real tag, and check what it published before the
  real tag: run the `e2e-published` workflow from the candidate's commit
  with the candidate's chart version (`<VERSION>-rc.<n>`, what its `check`
  job reports as `CHART_VERSION`), once per backend. The tag publishes the images under
  `v<VERSION>` (and `v<VERSION>-<commit>`), the chart as `<VERSION>`, signs
  them, and once `check` passes creates the GitHub Release with the pinned
  references and the `cosign verify` command in its notes, and the `grantc`
  binaries with their signed `checksums.txt` and the `cosign verify-blob`
  command. The tag path cannot run before a real tag: check a candidate's
  release assets with that command and with a grants repository's `check`
  run against the candidate before tagging the release. A tag that is not
  on `main`, or that does not match `VERSION` (the workspace status then
  reports a snapshot, not the release), is refused.
- After the release, set `VERSION` to the next one in a pull request.
- In 0.x a release may break the protocol between components or the chart's
  values; say so in the release notes when one does.

## Pull requests

- `main` takes squash merges with a linear history; the `ci` check aggregates
  the jobs.
- GitHub Actions are pinned by commit SHA, with the version in a comment.
- Keep a pull request to one slice of behaviour, with its tests.
