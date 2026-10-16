# Crachá: Workload AWS Credentials via SPIFFE Identity, a Credential Broker, a Pluggable Authorization Store and a Node Agent

Project: Crachá (`cracha`, https://cracha.dev) · Status: Draft · Owner: Bruno (platform) · Last updated: 2026-10-16

Naming: binaries and Kubernetes objects use the ASCII form `cracha-*`. The CSI driver, annotations and any API groups live under `cracha.dev` (e.g. `csi.cracha.dev`, `cracha.dev/enabled`).

## 1. Problem

IAM role quotas (1,000 roles per account by default, max 5,000) make "one IAM role per workload" unsustainable. Workloads still need different permissions. We need many logical permission sets backed by few IAM roles, with per-workload attribution and fast revocation, across any Kubernetes cluster, managed or self-hosted.

## 2. Goals / non-goals

Goals
- A few IAM roles per account, one per **permission shape** (e.g. `shape-s3-reader`, `shape-dynamo-rw`).
- Workload identity = **SPIFFE ID**, obtained through the standard SPIFFE Workload API from a pluggable issuer. SPIRE is the reference issuer, not a dependency of the design. Uniform across all clusters regardless of platform or cloud provider.
- Per-workload scope enforced via ABAC session tags and, where needed, **session policies** issued by a central broker.
- **Who may get what** lives in a **pluggable authorization store** behind a small, backend-neutral interface. SpiceDB is the reference backend, not a dependency of the design. **What a credential may look like** lives in a signed, Git-managed bundle.
- No application/SDK code changes. No AWS credentials on disk. The only on-disk secret in the default mode is a pod-scoped endpoint token that is useless outside that pod.
- CloudTrail attributes every call on a shared role to the real workload (`SourceIdentity`).
- Targeted revocation of live sessions for a single workload.

Non-goals
- Human access.
- Coupling the broker or node agent to one authorization engine or one identity issuer. Backend-specific types never leave their adapter package.
- Long-lived credentials.
- Replacing ABAC-only access (Path A) for the majority of workloads.

## 3. Architecture overview

Two credential paths share one identity system:

| Path | Use when | Mechanism |
|---|---|---|
| **A (default)** | Same actions, different resources | JWT-SVID → `sts:AssumeRoleWithWebIdentity` on a shape role; ABAC via session tags in the JWT |
| **C (broker)** | Permissions must be centrally narrowed and enforced | Node agent → mTLS (pod's X.509-SVID) → broker → authz check → `sts:AssumeRole` with session policy + tags |

(Path B, IAM Roles Anywhere with X.509-SVIDs, is reserved for non-AWS-hosted workloads and is out of scope for the first implementation.)

```mermaid
flowchart TB
    subgraph k8snode["Node"]
        subgraph pod["Pod"]
            app["app (AWS SDK)<br/>AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.2/v1/credentials<br/>AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/cracha/token"]
            helper["cracha-helper<br/>credential_process (opt-in)"]
            app -.->|exec| helper
        end
        agent["cracha-node (DaemonSet, hostNetwork)<br/>CSI node plugin + agent<br/>• NodePublish/Unpublish → pod registry, pod token<br/>• endpoint token + source IP attestation (default)<br/>• SO_PEERCRED attestation (credential_process)<br/>• per-pod X.509-SVID from the issuer<br/>• node credential cache"]
        issuer["identity issuer agent<br/>(SPIRE reference)"]
        app -->|"HTTP on 169.254.170.2 + pod token"| agent
        helper -.->|"Unix socket (opt-in)"| agent
        issuer -->|"per-pod SVIDs"| agent
    end
    broker["cracha-broker (per cluster, stateless, ≥3 replicas)<br/>authn (mTLS) → authz Check → grant bundle lookup<br/>→ render + envelope-validate session policy<br/>→ cache/singleflight → sts:AssumeRole (regional STS)"]
    authz["authz store<br/>(SpiceDB reference)"]
    bundle["grant bundle<br/>(signed, from Git)"]
    sts["STS"]
    shapes["Shape roles in target accounts<br/>(permission boundary + SCP ceiling)"]
    agent -->|"mTLS presenting the pod's SVID"| broker
    broker -->|Check| authz
    bundle -->|poll + verify| broker
    broker -->|"AssumeRole (broker's own creds via Path A)"| sts
    sts --> shapes
```

## 4. Identity

The design depends on the **SPIFFE standard**, not on a particular issuer. Any issuer that meets the contract in 4.1 can be used; SPIRE is the reference implementation (4.2).

- **SPIFFE ID scheme:** `spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>`. The scheme is enforced by the issuer's registration policy, whatever the issuer.
- The cluster is **not** part of the identity. The same workload running in several clusters of a trust domain has one SPIFFE ID, so active-active deployments share grants by default. Cluster is context: in Path C the broker knows which cluster it serves and attaches it; in Path A it is available only when the issuer can add claims. Per-cluster scoping is expressed as an assignment condition (6.4), never as a separate identity.
- The issuer is a Tier-0 service: signing keys in KMS/HSM, per-region deployment or a nested hierarchy under a shared root.
- Crachá is trust-domain-agnostic. Trust domain topology (one domain with a nested hierarchy, or several federated domains) is the issuer operator's choice. It touches Crachá in two places only: Path A needs one IAM OIDC provider per trust domain, and a workload's identity is scoped to its trust domain, so per-region domains give the same workload a different identity per region.
- The service mesh (Istio, multi-primary) should eventually consume the same issuer via Envoy SDS, so mesh identity == AWS identity. Not required for v1.

### 4.1 Identity issuer contract

What Crachá needs from the issuer, and the standard mechanism for each:

| Need | Used by | Standard mechanism | Adapter responsibility |
|---|---|---|---|
| Own X.509-SVID and trust bundle (incl. federated bundles) | broker, cracha-node | SPIFFE Workload API (`go-spiffe/v2`) | none, standard |
| JWT-SVID with `aud=sts.amazonaws.com` | Path A workloads, broker's own creds | SPIFFE Workload API | none, standard |
| OIDC discovery (JWKS) for the trust domain | IAM OIDC provider (Path A) | SPIFFE OIDC federation, public HTTPS endpoint | issuer-specific deployment |
| ABAC claims in JWT-SVIDs (`https://aws.amazon.com/tags`) | Path A | no standard | issuer hook where available; otherwise ABAC tags are derived by IAM from `sub` path segments (`StringLike` conditions) |
| **Per-pod X.509-SVID obtained by cracha-node on the pod's behalf** | cracha-node (Path C) | no standard | issuer adapter: subscribe to a pod's SVID stream keyed by pod UID; subscription dropped on unpublish |
| Node and workload attestation | all | issuer-specific | platform-specific attestor per cluster type (e.g. instance identity for cloud nodes, projected SA tokens for self-hosted clusters) |

Rules:
- The broker and Path A touch only the Workload API and are issuer-agnostic by construction.
- The per-pod delivery hook is the one issuer-specific piece. It sits behind an adapter so cracha-node has no issuer-specific code.
- Any issuer must guarantee: SVID rotation delivered before expiry, subscription for an unregistered pod UID rejected, subscription torn down on unpublish, trust bundle refresh.
- SPIRE is the reference issuer. Other SPIFFE-conformant issuers (e.g. cert-manager with csi-driver-spiffe, a mesh CA exposing the Workload API) need only the per-pod delivery adapter.

### 4.2 Reference issuer: SPIRE

- SPIRE server per region (or nested SPIRE under a shared upstream root). Keys via KMS/HSM UpstreamAuthority.
- Node attestation: `aws_iid` for EC2-backed nodes, `k8s_psat` for self-hosted clusters.
- Workload attestation: k8s workload attestor. Entries managed by SPIRE Controller Manager `ClusterSPIFFEID`.
- OIDC discovery: SPIRE OIDC Discovery Provider.
- ABAC claims: a **CredentialComposer** plugin adds `principal_tags` (ns, sa, cluster; plus service/team once the authz store is live).
- Per-pod SVID delivery: the **Delegated Identity API** on the agent's admin socket, selector `k8s:pod-uid:<uid>`, with `authorized_delegates` restricted to cracha-node's SPIFFE ID.

### 4.3 Identity encodings

Several systems restrict characters, so one deterministic encoding, owned by a single shared library, is used everywhere:

| Target | Constraint | Encoding |
|---|---|---|
| STS `SourceIdentity`, `RoleSessionName` | `[\w+=,.@-]`, 2–64 chars | `w.<td-short>.<ns>.<sa>`; if >64 chars → `w.h.<sha256 base32 prefix>` |
| Authz subject ID (SpiceDB object ID charset, the strictest backend considered) | `[a-zA-Z0-9/_\|\-=+]`, ≤1024 | `<td-short>/<ns>/<sa>` (no `.`/`:`; escape rule defined by the library) |
| Session tags | standard tag charset | raw `ns`, `sa`, `cluster` values |

The mapping (encoded → full SPIFFE ID) is logged at every issuance to keep audit reversible.

## 5. Path A: JWT-SVID direct federation (default)

- The issuer's OIDC discovery endpoint at a public HTTPS URL; registered as an IAM OIDC provider per trust domain.
- JWT-SVID with `aud=sts.amazonaws.com`, TTL ≤ 5 min, fetched through the Workload API.
- ABAC tags come from the `https://aws.amazon.com/tags` claim (`principal_tags`: ns, sa, cluster; plus service/team once the authz store is live) when the issuer can add it (SPIRE: CredentialComposer). Without that hook, policies fall back to `StringLike` conditions on the `sub` path segments, which covers ns/sa but not cluster, service or team.
- One role per shape; trust policy `StringLike` on `<provider>:sub` (scoped pattern) and allows `sts:TagSession`.
- Policies scope resources with `${aws:PrincipalTag/...}` and `aws:ResourceTag/...`.
- The broker's own credentials use Path A.

## 6. Path C: credential broker

### 6.1 Responsibilities split

- **Grant bundle (Git, signed):** shapes, base roles, policy templates, allowed ARN envelopes, profiles. Answers *what*.
- **Authorization store (pluggable, SpiceDB reference):** assignments of grants to services/workloads, service membership, ownership, temporary access. Answers *who*.

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
    params: { tables: [ledger, ledger-outbox] }   # or resolved via the authz store (Level 3)
  managedPolicyArns: []            # escape hatch for large policies (max 10)
  sessionTags: { team: payments }
  duration: 3600                   # optional; default 1h, capped at 1h by role chaining
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

### 6.3 Authorization store contract

The broker depends only on this contract. Each backend is an adapter chosen by configuration, and all adapters must give the same answers to the same questions.

| Question | Operation | Answer | Required |
|---|---|---|---|
| May this workload assume this grant? | Check(subject, grant, consistency) | allow/deny, the matching grant (ambiguity is a deny, see 6.5), ABAC tags such as service and team, a consistency token, a decision trace | yes |
| Which grants (profiles) may this workload assume? | ListGrants(subject, consistency) | grant list + consistency token | yes |
| Which resources of a kind may this workload use? | LookupResources(subject, kind, permission) | resource list, for Level 3 template filling | optional |
| What changed since this token? | Watch(since) | stream of assignment changes, for cache invalidation | optional; without it the cache degrades to TTL-only invalidation |

Rules:
- Subject = the workload's authz encoding (4.3) plus the cluster the broker serves. The subject never carries anything the workload can set itself.
- Consistency tokens are opaque outside the adapter. SpiceDB's zedToken is one implementation; a static backend may use a file hash. Callers may ask for minimize-latency or at-least-as-fresh(token).
- Any failure to answer is a deny. Backends never fail open.
- Time-bounded and cluster-bounded assignments are part of the model, not of one backend's caveat feature. A backend without native conditions evaluates them in its adapter.
- Backends: `static` (signed assignment file, for bootstrap, air-gapped or tiny installs) and `spicedb` (reference). OpenFGA or a Cedar-based store would be further adapters, not design changes.

### 6.4 Reference backend: SpiceDB

The model below is the reference. Another backend must express the same concepts (team, service, workload, grant, account, time-bounded and cluster-bounded assignment) and give equivalent answers to the questions in 6.3.

```zed
definition team {}

definition service {
  relation owner: team
  relation member: workload
}

definition workload {}            // id = idenc authz encoding

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
- **L1 (v1):** `Store.Check(subject, grant)` gates issuance (SpiceDB: `CheckPermission(grant#assume, workload)`).
- **L2 (v1):** service/team returned in `Decision.Tags` become session tags for ABAC.
- **L3 (later, exceptions only):** `Store.LookupResources` fills template resource lists; every ARN is validated against the grant envelope at runtime; violations reject the request.

Relationship writers (write access to the authz store is security-critical, whatever the backend). Where a writer reads its source of truth from is out of scope; what Crachá requires is that the writer is trusted and that no relationship is derived from anything the workload controls:

| Relationship | Source of truth | Writer |
|---|---|---|
| `service#owner`, `grant#assignee_service` | Git (CODEOWNERS) | `authz-reconciler` |
| `service#member@workload` | Service catalog / Git. **Never** workload-controlled annotations | `authz-reconciler` |
| Temporary / break-glass | Approval flow | `access-approver`, with caveat/expiry |

Deployment (SpiceDB): one instance per region on its own Postgres. The reconciler writes to every region through the backend adapter (regions stay independent).

### 6.5 Broker API

```
POST /v1/credentials          (mTLS; client SPIFFE ID from URI SAN)
{ "account": "111122223333", "profile": "default" }

200 { "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration",
      "grant": "payments-ledger-rw", "bundleVersion": "...", "consistencyToken": "..." }
403 { "reason": "no_grant" | "ambiguous" | "subject_suspended" | "envelope_violation" }

GET /v1/profiles              (mTLS) → profiles the caller can assume (`Store.ListGrants`)
```

The broker terminates mTLS itself with go-spiffe (trust bundle + federated bundles from its own Workload API). Exclude its port from Istio interception. Never trust proxy-asserted identity headers.

### 6.6 STS mechanics

- Broker's role (`cracha-broker`, per environment) → `AssumeRole` on shape roles. This is role chaining, so the session max is 1 hour. Session duration is configurable per grant and defaults to 1 hour; targeted revocation (6.8) covers the window.
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

### 6.7 Caching

- Broker cache key: `(account, grant, bundleVersion, encoded workload)`. In-memory only, singleflight on miss, refresh-ahead at ~70% TTL, never return creds with <20 min left.
- **Re-check the authz store on every issuance, including cache hits** (cheap at refresh frequency).
- `Store.Watch` invalidates affected cache entries on assignment changes. Backends without Watch degrade to TTL-only invalidation, and the broker exposes which mode is active.
- Consistency: minimize latency by default; at-least-as-fresh when a caller (approver/revocation tool) supplies a consistency token.
- Authz store unavailable: fail closed for new keys; serve cache hits only if the last successful check for that key is <10 min old.

### 6.8 Revocation

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

cracha-node is a DaemonSet that owns the pod registry on its node, holds the node credential cache, obtains per-pod SVIDs from the issuer, and hands credentials to pods in one of two modes:

| Mode | SDK mechanism | Attestation | Requires from the pod |
|---|---|---|---|
| **Endpoint (default)** | container-credentials protocol: `AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` | per-pod token + source IP == registered pod IP | an SDK that supports the token file; nothing else |
| **credential_process (opt-in)** | `AWS_CONFIG_FILE` with `credential_process` entries | `SO_PEERCRED` → PID → cgroup → pod UID | exec on the volume, a shell for most SDKs |

The mode is chosen per ServiceAccount (`cracha.dev/mode`, default `endpoint`). Both modes share the registry, the cache and the broker path.

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
├── token               per-pod endpoint token, random, generated at publish   (endpoint mode)
├── config              rendered per pod                                       (credential_process mode, or extra profiles)
├── bin/cracha-helper   static binary (CGO_ENABLED=0), matched to node arch    (credential_process mode)
└── agent.sock          Unix socket served by cracha-node                      (credential_process mode)
```

Rendered config, when present:

```ini
[default]
credential_process = /var/run/cracha/bin/cracha-helper --profile default
region = <from node topology.kubernetes.io/region>
sts_regional_endpoints = regional

[profile <another-profile>]
credential_process = /var/run/cracha/bin/cracha-helper --profile <another-profile> --account <account-id>
region = <...>
```

### 7.3 NodePublishVolume

1. Read pod UID, namespace, SA from the volume context (kubelet-supplied).
2. Verify the kubelet-provided bound SA token. Its pod-binding claims must match the volume-context pod UID.
3. Register the pod with its UID, identity and pod IP. Subscribe to its X.509-SVID through the issuer adapter (SPIRE: Delegated Identity API, `k8s:pod-uid:<uid>`).
4. Generate the per-pod endpoint token and bind it to the registry entry.
5. In credential_process mode, or when the workload has named profiles: fetch profiles from the broker (`GET /v1/profiles`) and render `config` atomically (write temp + rename).
6. Prefetch default credentials into the node cache.

Kubelet doesn't start containers until publish succeeds, so credentials are ready before app start.

`requiresRepublish`: re-validate the pod, rotate the token if compromised, re-render config when profiles change. SDKs usually parse the config only when a client is created, so new profiles appear on new clients/restarts. Removal is effective immediately via the broker.

`NodeUnpublishVolume`: drop the registry entry, the token, the SVID subscription and the cache refs.

### 7.4 Endpoint mode (default)

- cracha-node runs with `hostNetwork` and serves the container-credentials protocol on `169.254.170.2:80`. The address lives on a dummy interface: provided by machine config on platforms that allow it, otherwise created by an init container with `NET_ADMIN`. `169.254.170.23` stays reserved for the EKS Pod Identity agent, so both can coexist.
- The SDK sends `GET /v1/credentials` with the token from `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` in the `Authorization` header. SDKs re-read the token file on every refresh, so rotation needs no restart.
- Attestation: the token maps to exactly one registered pod, and the request's source IP must equal that pod's registered IP. hostNetwork callers are denied. Either check failing is a 403 with no further detail.
- Response is the container-credentials JSON (`AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`). `Expiration` is mandatory, so SDKs refresh.
- The endpoint serves the workload's `default` profile only, because the SDK supports a single endpoint URI per process. Workloads that need more than one shape get named profiles through credential_process entries in the rendered config, alongside the endpoint.
- Precondition: the CNI must deliver pod traffic to the node's link-local address unmasqueraded, so the source IP is the pod's real IP. Where the CNI masquerades or does not route link-local traffic to the host, the IP check is unsound and the endpoint must not be enabled.

Publish and request sequence:

```mermaid
sequenceDiagram
    participant K as kubelet
    participant N as cracha-node
    participant I as identity issuer
    participant P as pod (AWS SDK)
    participant B as cracha-broker

    Note over K,N: NodePublishVolume (before containers start)
    K->>N: NodePublishVolume(pod UID, ns, SA, bound SA token)
    N->>N: verify SA token claims match pod UID
    N->>N: register pod: UID, SPIFFE ID, pod IP (from kubelet)
    N->>I: subscribe per-pod X.509-SVID (pod UID)
    I-->>N: SVID stream
    N->>N: generate random token, bind to registry entry
    N-->>K: volume with /var/run/cracha/token
    K->>P: start containers (volume mounted, env injected)

    Note over P,N: credential fetch (every SDK refresh)
    P->>N: GET http://169.254.170.2/v1/credentials<br/>Authorization: token
    N->>N: token → registry entry (exactly one)
    N->>N: source IP == entry.pod IP? hostNetwork → deny
    alt cache hit for (workload, account, default)
        N-->>P: credentials JSON
    else miss or refresh due
        N->>B: POST /v1/credentials (mTLS with the pod's SVID)
        B-->>N: credentials
        N-->>P: credentials JSON
    end

    Note over K,N: NodeUnpublishVolume
    K->>N: NodeUnpublishVolume(pod UID)
    N->>N: drop registry entry, token, SVID subscription, cache refs
```

### 7.5 credential_process mode (opt-in)

- `cracha-helper` connects to `agent.sock`, requests `{profile, account}`, and prints credential_process JSON: `{"Version":1,"AccessKeyId","SecretAccessKey","SessionToken","Expiration"}`.
- cracha-node attests via `SO_PEERCRED` → PID → `/proc/<pid>/cgroup` → pod UID (requires `hostPID: true`). Re-validate after lookup to avoid PID-reuse races. Must match a registered pod.
- Use it where the IP-based check is unavailable (CNI precondition unmet) or where SO_PEERCRED attestation is explicitly wanted.

### 7.6 Common request path

- Node cache keyed by `(workload identity, account, profile)`, shared by pods of the same workload on the node. Refresh at 50% TTL.
- To the broker: one mTLS connection pool per workload identity, presenting that pod's SVID.

### 7.7 Webhook (`cracha-webhook`)

For ServiceAccounts annotated `cracha.dev/enabled: "true"`, inject the CSI inline volume and, per mode:
- endpoint: `AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.2/v1/credentials`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/cracha/token`
- credential_process: `AWS_CONFIG_FILE=/var/run/cracha/config`, `AWS_SDK_LOAD_CONFIG=1`
- both, when the workload has named profiles

It strips or rejects `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_WEB_IDENTITY_TOKEN_FILE` and any `AWS_CONTAINER_CREDENTIALS_*` / `AWS_CONTAINER_AUTHORIZATION_*` the pod set itself. Pods with their own `AWS_CONFIG_FILE` use merge mode (managed profiles + ConfigMap-provided profiles). IMDS is blocked for pods (hop limit 1 / CNI policy).

### 7.8 Workload requirements

Endpoint mode:
- An AWS SDK or CLI that supports `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`. This was added across first-party SDKs for EKS Pod Identity (releases from late 2023). Older SDKs support only the inline `AWS_CONTAINER_AUTHORIZATION_TOKEN`, which cannot rotate and is not offered.
- Nothing else: no exec, no shell, no config file.

credential_process mode:
- An SDK whose default chain reads the shared config file and supports `credential_process` (all first-party SDKs since 2018). Go SDK v1 additionally needs `AWS_SDK_LOAD_CONFIG=1`, which the webhook injects.
- The container can execute the helper: the CSI volume is mounted without `noexec`, and the helper is static and matches the node architecture.
- A POSIX `sh` on `PATH` for SDKs that spawn the process through a shell (Go, Java, JavaScript, .NET). Python and the CLI exec the helper directly.

### 7.9 cracha-node hardening

- Distroless, read-only rootfs, dedicated namespace. `hostNetwork` required for the endpoint. `NET_ADMIN` only in the init container that creates the dummy interface, and only where the platform does not provide it. `hostPID` only when credential_process mode is enabled on the node.
- The endpoint listens on the link-local address only, never on node or pod-network addresses.
- Issuer agent: the per-pod delivery hook is restricted to cracha-node's identity (SPIRE: admin socket with `authorized_delegates` = cracha-node's SPIFFE ID only). Registration entry restricted to the cracha-node SA/namespace.
- Alert on per-pod SVID subscriptions for pod UIDs absent from the node's kubelet view, and on endpoint requests whose token and source IP disagree.

## 8. Failure modes

| Failure | Behavior |
|---|---|
| Broker down | SDK-cached + node-cached creds keep running pods alive ~30 min+. New pods block at volume publish. |
| STS throttle/outage | Broker serves cache, retries with jitter, alerts on cache age. |
| Authz store down | Fail closed for new keys; bounded-staleness cache hits (<10 min since last check). |
| Identity issuer agent down | Existing SVIDs work until TTL; new pods block at publish. |
| cracha-node restart | Registry and tokens rebuilt from kubelet pods + existing CSI mounts; endpoint unavailable for seconds, SDK retries. |
| Bad/unsigned bundle | Keep last good bundle, alert. Never fail open. |

## 9. Threat model (summary)

| Compromise | Impact | Mitigation |
|---|---|---|
| App container | Its own grants | Read-only volume; the only on-disk secret is the pod's endpoint token, accepted only from that pod's IP on that node |
| Node | Pods on that node | Per-node parenting of workload entries, node attestation, short SVID TTL |
| Pod spoofing another pod's IP on the node | That pod's grants | Token required in addition to IP; CNI anti-spoofing; alert on token/IP mismatch |
| cracha-node | Pods on that node (≈ node) | Hardening §7.9, delegate alerts |
| Broker | Grants in its environment, capped by shape ceilings | Dedicated nodes, per-env roles, alert on shape-role assumption without `SourceIdentity` / by other principals |
| Grant repo | Misuse within shape envelopes | CODEOWNERS, `CheckNoNewAccess`, signed bundles |
| Authz store writes | Misassignment within shapes | Restricted writers, change-feed audit log, envelope check |
| Identity issuer (e.g. SPIRE server) | Mint any identity | Tier-0 controls, KMS/HSM keys |

## 10. Open questions

- Q1: Approval flow for temporary access: build vs reuse existing tooling.
- Q2: Use the kubelet-projected bound ServiceAccount token (audience `cracha-node`) as the endpoint token instead of a CSI-generated one. It would remove the CSI volume from endpoint mode entirely, at the cost of cracha-node validating tokens against the API server.

## 11. Invariants

These hold regardless of backend, issuer or platform. Any implementation must be able to demonstrate each one.

- Never fail open: an unavailable authz store, issuer or bundle results in denial, or in serving already-issued credentials within bounded staleness, never in broader access.
- Every rendered session policy is checked against the grant's envelope before STS is called.
- `SourceIdentity` is set on every assumed session and is reversible to a SPIFFE ID through the decision log.
- cracha-node writes no AWS credentials to disk in either mode. The endpoint token is not an AWS credential and is accepted only from its own pod.
- The cache never returns credentials with less than 20 minutes remaining.
- All identity encodings come from the single shared encoding library. Nothing hand-formats a SourceIdentity or an authz subject ID.
- Backend-specific and issuer-specific types never leave their adapter.
- Diagrams in this document are Mermaid.
