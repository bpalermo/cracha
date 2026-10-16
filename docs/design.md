# Crachá: Workload AWS Credentials via SPIFFE, a Credential Broker, SpiceDB and a Node Agent

Project: Crachá (`cracha`, https://cracha.dev) · Status: Draft · Owner: Bruno (platform) · Last updated: 2026-10-16

Naming: binaries and Kubernetes objects use the ASCII form `cracha-*`. The CSI driver, annotations and any API groups live under `cracha.dev` (e.g. `csi.cracha.dev`, `cracha.dev/enabled`).

## 1. Problem

IAM role quotas (1,000 roles per account by default, max 5,000) make "one IAM role per workload" unsustainable. Workloads still need different permissions. We need many logical permission sets backed by few IAM roles, with per-workload attribution and fast revocation, across EKS and Talos clusters.

## 2. Goals / non-goals

Goals
- A few IAM roles per account, one per **permission shape** (e.g. `shape-s3-reader`, `shape-dynamo-rw`).
- Workload identity = **SPIFFE ID** issued by SPIRE, uniform across EKS and Talos.
- Per-workload scope enforced via ABAC session tags and, where needed, **session policies** issued by a central broker.
- **Who may get what** lives in **SpiceDB**. **What a credential may look like** lives in a signed, Git-managed bundle.
- No application/SDK code changes. No bearer secrets on disk or on the network in the default mode.
- CloudTrail attributes every call on a shared role to the real workload (`SourceIdentity`).
- Targeted revocation of live sessions for a single workload.

Non-goals
- Human access.
- Long-lived credentials.
- Replacing ABAC-only access (Path A) for the majority of workloads.

## 3. Architecture overview

Two credential paths share one identity system:

| Path | Use when | Mechanism |
|---|---|---|
| **A (default)** | Same actions, different resources | JWT-SVID → `sts:AssumeRoleWithWebIdentity` on a shape role; ABAC via session tags in the JWT |
| **C (broker)** | Permissions must be centrally narrowed and enforced | Node agent → mTLS (pod's X.509-SVID) → broker → SpiceDB check → `sts:AssumeRole` with session policy + tags |

(Path B, IAM Roles Anywhere with X.509-SVIDs, is reserved for non-AWS-hosted workloads and is out of scope for the first implementation.)

```
┌──────────────────────────── Node ─────────────────────────────┐
│ Pod                                                           │
│  app (AWS SDK)  AWS_CONFIG_FILE=/var/run/cracha/config        │
│   └─ credential_process → /var/run/cracha/bin/cracha-helper   │
│          │ Unix socket /var/run/cracha/agent.sock             │
│          ▼                                                    │
│ cracha-node (DaemonSet: CSI node plugin + agent, hostPID)     │
│   ├─ NodePublish/Unpublish → pod registry, renders config     │
│   ├─ SO_PEERCRED → PID → cgroup → pod UID attestation         │
│   ├─ SPIRE Delegated Identity API → X.509-SVID per pod        │
│   └─ node credential cache                                    │
│          │ mTLS presenting the pod's SVID                     │
│ spire-agent (authorized_delegates: cracha-node)               │
└──────────┼────────────────────────────────────────────────────┘
           ▼
 cracha-broker (per cluster, stateless, ≥3 replicas)
   authn (mTLS) → SpiceDB CheckPermission → grant bundle lookup
   → render + envelope-validate session policy → cache/singleflight
   → sts:AssumeRole (regional STS)
           │ broker's own creds via Path A
           ▼
 Shape roles in target accounts (permission boundary + SCP ceiling)
```

## 4. Identity (SPIRE)

- SPIRE server per region (or nested SPIRE under a shared upstream root). Keys via KMS/HSM UpstreamAuthority. Tier-0 service.
- Node attestation: `aws_iid` (EC2/EKS), `k8s_psat` (Talos).
- Workload attestation: k8s workload attestor. Entries managed by SPIRE Controller Manager `ClusterSPIFFEID`.
- **SPIFFE ID scheme:** `spiffe://<trust-domain>/c/<cluster>/ns/<namespace>/sa/<serviceaccount>` (see open question Q1 on whether to include the cluster).
- Istio (multi-primary) should eventually consume SPIRE via Envoy SDS, so mesh identity == AWS identity. Not required for v1.

### 4.1 Identity encodings (single shared library: `pkg/idenc`)

Several systems restrict characters, so one deterministic encoding is used everywhere:

| Target | Constraint | Encoding |
|---|---|---|
| STS `SourceIdentity`, `RoleSessionName` | `[\w+=,.@-]`, 2–64 chars | `w.<td-short>.<ns>.<sa>`; if >64 chars → `w.h.<sha256 base32 prefix>` |
| SpiceDB object ID | `[a-zA-Z0-9/_\|\-=+]`, ≤1024 | `<td-short>/<ns>/<sa>` (no `.`/`:`; escape rule defined in lib) |
| Session tags | standard tag charset | raw `ns`, `sa`, `cluster` values |

The mapping (encoded → full SPIFFE ID) is logged at every issuance to keep audit reversible.

## 5. Path A: JWT-SVID direct federation (default)

- SPIRE OIDC Discovery Provider at a public HTTPS endpoint; registered as an IAM OIDC provider per trust domain.
- JWT-SVID with `aud=sts.amazonaws.com`, TTL ≤ 5 min.
- A SPIRE **CredentialComposer** plugin adds the `https://aws.amazon.com/tags` claim (`principal_tags`: ns, sa, cluster; plus service/team once SpiceDB is live).
- One role per shape; trust policy `StringLike` on `<provider>:sub` (scoped pattern) and allows `sts:TagSession`.
- Policies scope resources with `${aws:PrincipalTag/...}` and `aws:ResourceTag/...`.
- The broker's own credentials use Path A.

## 6. Path C: credential broker

### 6.1 Responsibilities split

- **Grant bundle (Git, signed):** shapes, base roles, policy templates, allowed ARN envelopes, profiles. Answers *what*.
- **SpiceDB:** assignments of grants to services/workloads, service membership, ownership, temporary access. Answers *who*.

### 6.2 Grant definition (bundle)

```yaml
kind: Grant
metadata:
  name: payments-ledger-rw
spec:
  account: "111122223333"
  baseRole: arn:aws:iam::111122223333:role/broker/shape-dynamo-rw
  profile: default                 # named profiles for workloads needing >1 shape
  sessionPolicy:
    template: dynamo-table-rw
    params: { tables: [ledger, ledger-outbox] }   # or resolved via SpiceDB (Level 3)
  managedPolicyArns: []            # escape hatch for large policies (max 10)
  sessionTags: { team: payments }
  duration: 3600
  envelope:                        # runtime ARN allowlist for rendered policies
    - arn:aws:dynamodb:*:111122223333:table/payments-*
```

CI (`grant-compiler`) pipeline:
1. Render templates.
2. Access Analyzer `ValidatePolicy`.
3. `CheckNoNewAccess` against the shape's envelope policy.
4. Size budget lint (2,048-char inline session policy + packed tag budget).
5. Uniqueness: at most one grant per (profile, account) per assignee.
6. Compile → sign (KMS or cosign) → publish to S3.

Broker polls the bundle, verifies signature, swaps atomically, and **keeps the last good bundle on failure (never fails open).**

### 6.3 SpiceDB schema

```zed
definition team {}

definition service {
  relation owner: team
  relation member: workload
}

definition workload {}            // id = idenc SpiceDB encoding

definition aws_account {}

caveat within_window(expires_at timestamp, now timestamp) {
  now < expires_at
}

caveat in_clusters(allowed list<string>, cluster string) {
  cluster in allowed
}

definition grant {
  relation account: aws_account
  relation assignee_service: service | service with in_clusters
  relation assignee_workload: workload with within_window
  permission assume = assignee_service->member + assignee_workload
}

definition dynamodb_table {       // Level 3 only
  relation account: aws_account
  relation writer: service
  relation reader: service
  permission write = writer->member
  permission read  = write + reader->member
}
```

Integration levels:
- **L1 (v1):** `CheckPermission(grant#assume, workload)` gates issuance.
- **L2 (v1):** service/team from SpiceDB become session tags for ABAC.
- **L3 (later, exceptions only):** `LookupResources` fills template resource lists; every ARN is validated against the grant envelope at runtime; violations reject the request.

Relationship writers (SpiceDB write access is security-critical):

| Relationship | Source of truth | Writer |
|---|---|---|
| `service#owner`, `grant#assignee_service` | Git (CODEOWNERS) | `spicedb-reconciler` |
| `service#member@workload` | Service catalog / Git. **Never** workload-controlled annotations | `spicedb-reconciler` |
| Temporary / break-glass | Approval flow | `access-approver`, with caveat/expiry |

Deployment: SpiceDB per region on its own Postgres. Reconciler writes to every region (regions stay independent).

### 6.4 Broker API

```
POST /v1/credentials          (mTLS; client SPIFFE ID from URI SAN)
{ "account": "111122223333", "profile": "default" }

200 { "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration",
      "grant": "payments-ledger-rw", "bundleVersion": "...", "zedToken": "..." }
403 { "reason": "no_grant" | "ambiguous" | "subject_suspended" | "envelope_violation" }

GET /v1/profiles              (mTLS) → profiles the caller can assume (SpiceDB LookupResources)
```

The broker terminates mTLS itself with go-spiffe (trust bundle + federated bundles from its own Workload API). Exclude its port from Istio interception. Never trust proxy-asserted identity headers.

### 6.5 STS mechanics

- Broker's role (`cracha-broker`, per environment) → `AssumeRole` on shape roles. This is role chaining, so the session max is 1 hour.
- Each call sets:
  - `SourceIdentity` = `RoleSessionName` = idenc STS encoding (per workload, not per pod)
  - `Policy` / `PolicyArns` = rendered session policy
  - session tags: `spiffe-ns`, `spiffe-sa`, `cluster`, `grant`, `team`, `service` (non-transitive)
- Shape role trust policy:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::PLATFORM:role/cracha-broker-prod" },
  "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"],
  "Condition": {
    "StringLike": { "sts:SourceIdentity": "w.*" },
    "ForAllValues:StringEquals": {
      "aws:TagKeys": ["spiffe-ns", "spiffe-sa", "cluster", "grant", "team", "service"]
    }
  }
}
```

- Shape role ceiling: permission boundary with explicit denies on `iam:*`, `sts:AssumeRole*`, `organizations:*`, key administration; backed by SCPs.
- Separate `cracha-broker` roles per environment/account tier. A dev broker can't assume prod shapes.

### 6.6 Caching

- Broker cache key: `(account, grant, bundleVersion, encoded workload)`. In-memory only, singleflight on miss, refresh-ahead at ~70% TTL, never return creds with <20 min left.
- **Re-check SpiceDB on every issuance, including cache hits** (cheap at refresh frequency).
- SpiceDB **Watch** subscription invalidates affected cache entries on relationship changes.
- Consistency: `minimize_latency` by default; `at_least_as_fresh(zedToken)` when a caller (approver/revocation tool) supplies a token.
- SpiceDB unavailable: fail closed for new keys; serve cache hits only if the last successful check for that key is <10 min old.

### 6.7 Revocation

1. Stop issuance: remove the relationship (or suspend the grant in the bundle) and flush the cache via Watch.
2. Kill live sessions: `revoke-tool` attaches an inline deny to the shape role, scoped to one workload, and removes it after 1h:

```json
{ "Effect": "Deny", "Action": "*", "Resource": "*",
  "Condition": {
    "StringEquals": { "aws:SourceIdentity": "w.prod.payments.ledger" },
    "DateLessThan": { "aws:TokenIssueTime": "2026-10-16T14:00:00Z" } } }
```

Optionally triggered automatically when Watch observes an assignment deletion.

## 7. Delivery: cracha-node (CSI + node agent)

### 7.1 CSIDriver

```yaml
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: csi.cracha.dev
spec:
  attachRequired: false
  podInfoOnMount: true
  volumeLifecycleModes: [Ephemeral]
  requiresRepublish: true
  tokenRequests:
    - audience: cracha-node
      expirationSeconds: 600
```

### 7.2 Volume contents (read-only to the container, plugin-owned)

```
/var/run/cracha/
├── config              rendered per pod
├── bin/cracha-helper   static binary (CGO_ENABLED=0), matched to node arch
└── agent.sock          Unix socket served by cracha-node
```

Rendered config:

```ini
[default]
credential_process = /var/run/cracha/bin/cracha-helper --profile default
region = <from node topology.kubernetes.io/region>
sts_regional_endpoints = regional

[profile archive]
credential_process = /var/run/cracha/bin/cracha-helper --profile archive --account 444455556666
region = <...>
```

### 7.3 NodePublishVolume

1. Read pod UID, namespace, SA from the volume context (kubelet-supplied).
2. Verify the kubelet-provided bound SA token. Its pod-binding claims must match the volume-context pod UID.
3. Register the pod. Subscribe to its X.509-SVID via the SPIRE Delegated Identity API (`k8s:pod-uid:<uid>`).
4. Fetch profiles from the broker (`GET /v1/profiles`) and render `config` atomically (write temp + rename).
5. Prefetch default credentials into the node cache.

Kubelet doesn't start containers until publish succeeds, so credentials are ready before app start.

`requiresRepublish`: re-validate the pod, re-render config when profiles change. Note: SDKs usually parse the config only when a client is created, so new profiles appear on new clients/restarts. Removal is effective immediately via the broker.

`NodeUnpublishVolume`: drop the registry entry, the SVID subscription and the cache refs.

### 7.4 Request path and attestation

- `cracha-helper` connects to `agent.sock`, requests `{profile, account}`, and prints credential_process JSON: `{"Version":1,"AccessKeyId","SecretAccessKey","SessionToken","Expiration"}`. `Expiration` is mandatory, so SDKs refresh.
- cracha-node attests via `SO_PEERCRED` → PID → `/proc/<pid>/cgroup` → pod UID (requires `hostPID: true`). Re-validate after lookup to avoid PID-reuse races. Must match a registered pod.
- Node cache keyed by `(workload identity, account, profile)`, shared by pods of the same workload on the node. Refresh at 50% TTL.
- To the broker: one mTLS connection pool per workload identity, presenting that pod's SVID.

### 7.5 Webhook (`cracha-webhook`)

For ServiceAccounts annotated `cracha.dev/enabled: "true"`, inject:
- the CSI inline volume
- `AWS_CONFIG_FILE=/var/run/cracha/config`, `AWS_SDK_LOAD_CONFIG=1`

It strips or rejects `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_CONTAINER_CREDENTIALS_*`. Pods with their own `AWS_CONFIG_FILE` use merge mode (managed profiles + ConfigMap-provided profiles). IMDS is blocked for pods (hop limit 1 / CNI policy).

### 7.6 Fallback mode: link-local endpoint (opt-in)

For workloads that can't use credential_process:
- cracha-node serves the container-credentials protocol on `169.254.170.2` (dummy interface; Talos via machine config, EKS needs `NET_ADMIN`). `.23` stays reserved for the EKS Pod Identity agent.
- The CSI volume additionally contains a per-pod random token. Inject `AWS_CONTAINER_CREDENTIALS_FULL_URI` and `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`.
- Validate token + **source IP == registered pod IP**. hostNetwork callers are denied.

### 7.7 cracha-node hardening

- Distroless, read-only rootfs, dedicated namespace. `hostPID` required. No `NET_ADMIN` unless fallback mode is enabled on EKS.
- SPIRE agent: admin socket enabled, `authorized_delegates` = cracha-node's SPIFFE ID only. Registration entry restricted to the cracha-node SA/namespace.
- Alert on delegated-identity subscriptions for pod UIDs absent from the node's kubelet view.

## 8. Failure modes

| Failure | Behavior |
|---|---|
| Broker down | SDK-cached + node-cached creds keep running pods alive ~30 min+. New pods block at volume publish. |
| STS throttle/outage | Broker serves cache, retries with jitter, alerts on cache age. |
| SpiceDB down | Fail closed for new keys; bounded-staleness cache hits (<10 min since last check). |
| SPIRE agent down | Existing SVIDs work until TTL; new pods block at publish. |
| cracha-node restart | Registry rebuilt from kubelet pods + existing CSI mounts; brief errors, SDK retries. |
| Bad/unsigned bundle | Keep last good bundle, alert. Never fail open. |

## 9. Threat model (summary)

| Compromise | Impact | Mitigation |
|---|---|---|
| App container | Its own grants | Read-only volume, no secrets on disk (default mode) |
| Node | Pods on that node | SPIRE per-node parenting, node attestation, short SVID TTL |
| cracha-node | Pods on that node (≈ node) | Hardening §7.7, delegate alerts |
| Broker | Grants in its environment, capped by shape ceilings | Dedicated nodes, per-env roles, alert on shape-role assumption without `SourceIdentity` / by other principals |
| Grant repo | Misuse within shape envelopes | CODEOWNERS, `CheckNoNewAccess`, signed bundles |
| SpiceDB writes | Misassignment within shapes | Restricted writers, Watch-based audit log, envelope check |
| SPIRE server | Mint any identity | Tier-0 controls, KMS/HSM keys |

## 10. Observability & audit

- Broker metrics:
  - `cracha_issue_total{result,grant}`
  - `cracha_cache_hit_ratio`
  - `sts_latency_seconds`
  - `sts_errors_total{code}`
  - `packed_policy_pct` (from STS `PackedPolicySize`)
  - `bundle_age_seconds`
  - `spicedb_check_latency_seconds`
- cracha-node metrics:
  - `registered_pods`
  - `svid_subscriptions`
  - `helper_requests_total{result}`
  - `cracha_cred_remaining_seconds`
- Decision log (structured, per issuance):
  - SPIFFE ID, encoded SourceIdentity, account, profile, grant, bundle version, zedToken
  - **the SpiceDB permission path** (debug trace), because SpiceDB revision replay is limited by its GC window
- CloudTrail detections:
  - shape-role assumptions not by the broker
  - unknown SourceIdentity
  - deny spikes per workload

## 11. Repository layout (proposed, Go)

```
cmd/
  cracha-broker/      broker service
  cracha-node/        CSI node plugin + node agent
  cracha-helper/      credential_process helper (static)
  cracha-webhook/     mutating admission webhook
  grant-compiler/     CI: render, validate, sign bundle
  spicedb-reconciler/ Git/catalog → SpiceDB relationships
  revoke-tool/        targeted session revocation
pkg/
  idenc/              identity encodings (STS, SpiceDB, tags) + tests
  bundle/             bundle schema, signature verification, hot reload
  authz/              SpiceDB client, caveat context, Watch invalidation
  stsx/               AssumeRole wrapper, session policy rendering, envelope check
  cache/              singleflight + refresh-ahead cache
  attest/             SO_PEERCRED → pod UID resolution
  credproto/          credential_process JSON + container-credentials formats
schema/spicedb/       schema.zed + validation file (zed validate)
grants/               Grant YAMLs, templates, envelopes
deploy/               Helm/Kustomize for all components, CSIDriver, SPIRE config
iac/                  OpenTofu/Terraform: shape roles, trust policies, boundaries, OIDC provider
docs/                 this document, runbooks
```

Libraries: `go-spiffe/v2`, `aws-sdk-go-v2`, `authzed-go`, `container-storage-interface/spec`, `controller-runtime` (webhook/reconciler).

## 12. Implementation plan

Each milestone ships with tests and is independently deployable to a staging account/cluster.

**M0 – Foundations**
- `pkg/idenc` with property tests: deterministic, charset-valid, ≤64 chars, collision-resistant hash fallback.
- `pkg/credproto`.
- IaC: one shape role, permission boundary, `cracha-broker` role, OIDC provider.

Done when: encodings are fuzz-tested and the IaC plan applies cleanly in staging.

**M1 – Identity**
- SPIRE server/agent, Controller Manager, `ClusterSPIFFEID` templates, OIDC discovery provider.
- Path A working for one test workload, with ABAC tags via CredentialComposer.

Done when: CloudTrail shows the tagged web-identity session; ABAC policy allows/denies as expected.

**M2 – Broker core (static authz)**
- mTLS authn, bundle loading/signature verification, STS issuance with SourceIdentity/tags/session policy, cache.
- Temporary static assignment file in place of SpiceDB.

Done when: integration tests show issuance, envelope rejection, cache hit ratio, last-good-bundle behavior.

**M3 – SpiceDB**
- Schema + `zed validate` assertions.
- Reconciler from Git.
- L1 check + L2 tags; Watch invalidation; zedToken consistency; bounded staleness.

Done when: removing a relationship stops issuance on the next request carrying the writer's zedToken.

**M4 – cracha-node + helper + webhook**
- CSI ephemeral volume, config rendering, Delegated Identity API, SO_PEERCRED attestation, node cache, webhook injection/stripping.

Done when: an unmodified app using AWS SDK default chain gets credentials; a different pod on the same node can't obtain them; pod deletion clears state.

**M5 – Revocation & ops**
- `revoke-tool`, Watch-triggered auto-revocation (flagged), metrics, decision log, CloudTrail detections, runbooks.
- Failure drills (§8).

**M6 – Fallback & extras**
- Link-local fallback mode.
- Level 3 `LookupResources` with envelope enforcement.
- Istio SPIRE integration (separate track).

## 13. Open questions

- Q1: Include cluster in SPIFFE ID path? (Cluster-agnostic access for active-active vs per-cluster scoping.)
- Q2: One trust domain with nested SPIRE vs per-region trust domains with federation (affects IAM OIDC provider count, max 100/account).
- Q3: Source of truth for `service#member@workload`: Backstage/catalog vs Git.
- Q4: Default session duration (1h with targeted revocation vs 30 min).
- Q5: Approval flow for temporary access: build vs reuse existing tooling.
- Q6: Minimum SDK versions across the fleet that support `credential_process` in the default chain.
- Q7: Validate pod→node link-local routing on VPC CNI and Cilium before enabling fallback mode.

## 14. Notes for coding agents

- Treat this document as the source of truth. Propose changes to it in the same PR as code that diverges.
- Security invariants (must have tests):
  - never fail open
  - envelope check on every rendered policy
  - SourceIdentity always set
  - no credentials written to disk by cracha-node in default mode
  - cache never returns creds with <20 min remaining
- All identity encoding goes through `pkg/idenc`. Never hand-format SourceIdentity or SpiceDB IDs.
- Prefer table-driven tests. Use localstack/moto only for STS shape tests; validate real IAM behavior in the staging account.
