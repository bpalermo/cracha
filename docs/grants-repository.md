# The grants repository

The grants every cluster's broker serves (design 6.2) live outside this
repository, in **`bpalermo/cracha-grants`**, which is **private**. Its CI runs
the grant pipeline with a released `grantc` and the reusable workflow
[`.github/workflows/grants.yml`](../.github/workflows/grants.yml) of this
repository, so it never builds Crachá:

| Event | Mode | What runs | Role it assumes |
|---|---|---|---|
| pull request | `check` | lint (with IAM Access Analyzer) and compile; nothing is written | `gha-cracha-grants-check` |
| push to `main` | `publish` | the same, then sign with KMS, verify, publish to S3 | `gha-cracha-grants-publish` |

A private caller works because everything it fetches from here is public:
the reusable workflow, and the `grantc` binaries attached to each Crachá
release. Nothing from the grants repository is ever published anywhere
except the signed bundle the publish job writes to S3, and that bucket is
private too.

## What grants.yml does

1. Checks its inputs, before anything is downloaded or assumed.
2. Checks the caller's repository out (without persisting the token).
3. In `publish` mode, refuses a commit that is no longer its branch's tip,
   so a slow run of an older merge cannot move `latest` backwards; runs
   that publish to one destination are serialized.
4. Installs cosign at the version and sha256 this repository pins
   (`//bazel/cosign:workflow_pin_test` keeps the two equal).
5. Downloads `grantc_<version>_linux_<arch>`, `checksums.txt` and
   `checksums.txt.sigstore.json` from the release `grantc-version` names,
   verifies the signature of `checksums.txt` keyless against the identity
   `https://github.com/bpalermo/cracha/.github/workflows/publish.yml@refs/tags/<grantc-version>`
   and the issuer `https://token.actions.githubusercontent.com`, checks the
   binary's sha256 against it, and requires `grantc --version` to report
   that release.
6. Assumes `role-to-assume` through GitHub OIDC
   (`aws-actions/configure-aws-credentials`), when the mode is `publish` or
   Access Analyzer is on.
7. `grantc lint` the tree, with `-access-analyzer` unless `access-analyzer`
   is false.
8. `grantc compile`, the bundle's version being the commit
   (`-version <sha>`). In `publish` mode compile repeats the full lint, so
   the bundle signed is the one that passed it.
9. `publish` mode only: `grantc sign -kms-key` (kms:Sign; the signature's
   `keyId` is the sha256 of the key's public key), `grantc verify -kms-key`
   (the key's public key from kms:GetPublicKey, checked locally, as the
   broker will check it, before anything is written), then
   `grantc publish -s3 <destination>`, which writes
   `bundles/<version>/bundle.json`, its `.sig` and then `latest`.

Inputs:

| Input | Default | |
|---|---|---|
| `grantc-version` | required | a Crachá release tag, `vX.Y.Z` or `vX.Y.Z-rc.N` |
| `source` | `.` | the grant tree, relative to the checkout |
| `mode` | required | `check` or `publish` |
| `aws-region` | | the region of the AWS calls; required with a role |
| `role-to-assume` | | the role ARN; required in `publish` mode and for Access Analyzer |
| `kms-key` | | `publish`: the signing key, a key or alias ARN |
| `destination` | | `publish`: `s3://bucket/prefix` |
| `access-analyzer` | `true` | run `ValidatePolicy` and `CheckNoNewAccess` |

The output `bundle-version` is the version compiled (and published).

## The caller's workflows

The two files of `bpalermo/cracha-grants`. Both grant `id-token: write` and
`contents: read` (a reusable workflow gets no more than its caller gives
it), and **neither job runs in a GitHub environment**: an environment
changes the OIDC token's subject to `repo:<owner>/<repo>:environment:<name>`,
which the roles' trust policies below refuse.

Pin the reusable workflow by the commit SHA of a Crachá release tag, with the
tag in a comment, and give the same release as `grantc-version`. Moving to a
new release is changing both together. `<sha>` is
`gh api repos/bpalermo/cracha/commits/<tag> --jq .sha`, the commit the tag points at (release tags are annotated, so `git/ref/tags/<tag>` names the tag object, which `uses:` does not accept). `grantc` skips hidden directories under `source`, so the tree can be the repository's root beside `.github/`.

The workflow needs a `grantc` that writes the KMS key's public-key hash as
the signature's `keyId` and verifies `-kms-key` locally after
kms:GetPublicKey: a Crachá release that includes that change, `v0.1.0-rc.3`
or later. Earlier releases have no `grants.yml` and no `grantc` assets
either.

`.github/workflows/check.yml`:

```yaml
name: check
on:
  pull_request:

permissions:
  contents: read
  id-token: write

jobs:
  grants:
    uses: bpalermo/cracha/.github/workflows/grants.yml@<sha> # v0.1.0
    with:
      grantc-version: v0.1.0
      mode: check
      aws-region: sa-east-1
      role-to-assume: arn:aws:iam::988966554486:role/gha-cracha-grants-check
```

`.github/workflows/publish.yml`:

```yaml
name: publish
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  grants:
    # No `environment:` here (see above).
    uses: bpalermo/cracha/.github/workflows/grants.yml@<sha> # v0.1.0
    with:
      grantc-version: v0.1.0
      mode: publish
      aws-region: sa-east-1
      role-to-assume: arn:aws:iam::988966554486:role/gha-cracha-grants-publish
      kms-key: arn:aws:kms:sa-east-1:988966554486:alias/cracha-grants-signing
      destination: s3://cracha-grants-988966554486/grants
```

Protect `main` so that a change reaches it only through a pull request whose
`check` passed: the publish job signs whatever `main` holds.

## The tree

`grantc` loads every YAML file of the tree by its `kind` and the session
policy templates from `templates/`; the directories are a convention for
people:

```
accounts/      kind: Account, one per AWS account: its role, envelope and access table
access/        kind: Access, a workload's or a service's relation to a resource
templates/     session policy templates, <name>.json
services/      kind: Service, a team's workloads and their shared grants
grants/        kind: Grant, a grant written out (optional)
assignments/   kind: Assignment, one workload's own grants or its suspension
```

The default model is one IAM role per account, the **account role**, shared
by every application of the account (design 6.6): a broad identity policy,
held in by a permission boundary and SCPs, and the session policy the
broker composes for each workload does all the scoping. A team then writes
relationships, not grants: "this workload reads that bucket" is an Access
document, and what reading a bucket of the account means in IAM is one
line of the account's access table.

A minimal tree is one Account document, a template, and Access documents.
As an illustration only (the account and the names are examples; the real
tree lives in the grants repository):

`accounts/apps.yaml`:

```yaml
kind: Account
metadata:
  name: apps                 # free; it names the implicit grants
spec:
  id: "111122223333"
  role: arn:aws:iam::111122223333:role/cracha/apps    # the account role
  envelope:                  # default envelope of the account's grants
    - arn:aws:s3:::example-*
  access:                    # what read and write mean, per resource kind
    - kind: s3_bucket
      permission: read
      template: s3-read      # its one open parameter takes the buckets
    - kind: s3_bucket
      permission: write
      template: s3-write
      param: buckets         # needed when the template leaves more open
      params: {prefix: incoming/}
      duration: 1800         # optional, as on a Grant; so is sessionTags
```

`templates/s3-read.json`:

```json
{
  "params": {"bucket": {"type": "string"}},
  "policy": {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::${bucket}/*"
    }]
  }
}
```

`access/reports-exports.yaml`:

```yaml
kind: Access
metadata:
  name: reports-exports
spec:
  service: reports-api      # its members; or subject: prod/reports/worker
  resource: {kind: s3_bucket, name: example-exports}
  relation: reader          # reader gives read; writer gives read and write
  expiresAt: "2027-06-30T00:00:00Z"   # optional, as on an Assignment
  clusters: [prod-sa-east-1]          # optional
```

`services/reports-api.yaml` (a service gives its members the `team` and
`service` session tags, and lets one Access document cover them all):

```yaml
kind: Service
metadata:
  name: reports-api
spec:
  team: reports
  members:
    - prod/reports/api
```

Every entry of an access table is an **implicit grant**, compiled into the
bundle under the name `account:<account name>:<kind>:<permission>`
(`account:apps:s3_bucket:read` above) and shown under that name by
`grantc lint`, in `Cracha-Grants`, in `/v1/grants`, in the `grant` session
tag and in the broker's decision log. Nothing assigns it: the broker
applies it to a workload the Access documents relate to a resource of the
kind in the account, rendered with those resources (once per bucket for a
`string` parameter like `bucket`, all at once for a `list` one), on the
account role, inside the account's envelope, and refuses the credential
(`resource_outside_envelope`) when one falls outside it. A workload with no
grant and no relation gets nothing (`no_grant`). `grantc lint` reports,
per implicit grant, how many resources of the longest name its policy can
hold, and per workload, the resources it will be rendered with.

A resource is in the account its Access document's `resource.account`
names (the 12-digit id), or in the tree's only Account when it names none;
with more than one Account document every Access document names it. One
credential is one account: a workload whose relations span two accounts is
refused (`accounts_mixed`), and the lint says so for the relations in Git.

Grants can still be written out, beside the access tables, for what a
relation does not express: a policy that names its resources itself,
managed policies, a different duration. A grant of an account with an
Account document may leave out `baseRole` and `envelope`, which are then
the account's. `grants/reports-admin.yaml`:

```yaml
kind: Grant
metadata:
  name: reports-admin
spec:
  account: "111122223333"   # the account role and envelope apply
  sessionPolicy:
    template: s3-read
    params: {bucket: example-reports-admin}
```

assigned to a service (`grants: [{name: reports-admin}]`) or to one
workload (`assignments/reports-worker.yaml`):

```yaml
kind: Assignment
metadata:
  name: reports-worker
spec:
  subject: prod/reports/worker
  grants: [reports-admin]
  expiresAt: "2027-06-30T00:00:00Z"
```

`baseRole` is the override: a grant that names one is issued on that
dedicated shape role instead of the account role, for the few workloads a
shared role cannot serve (a role another account trusts by name, say). All
of a workload's grants must still share one role, so a workload holding a
dedicated-shape grant and related to resources of the account role's
implicit grants is refused (`ambiguous`), and the lint says so.

A written grant may also leave one parameter to a lookup, `bucket:
{lookup: {kind: s3_bucket, permission: read}}`, rendered with the
workload's resources like an implicit grant: a workload holding such a
grant gets it, and not the account's implicit grant, for that kind and
permission.

Run the same lint locally with a release binary:
`grantc lint .` (add `-access-analyzer -region sa-east-1` with AWS
credentials).

## The AWS side

In account `988966554486`, region `sa-east-1` (managed in Terraform, not
here). The repositories use GitHub's immutable OIDC subjects, so a token's
`sub` names the owner and the repository with their numeric IDs,
`repo:<owner>@<owner id>/<repo>@<repo id>:...`, not the plain
`repo:<owner>/<repo>:...`: a trust written in the plain form refuses every
run with "Not authorized to perform sts:AssumeRoleWithWebIdentity". Read
the prefix with `gh api repos/<owner>/<repo>/actions/oidc/customization/sub`.

- **`gha-cracha-grants-check`**, trusted for the GitHub OIDC provider with
  `sub` `repo:bpalermo@4821983/cracha-grants@1424650328:pull_request` and `aud`
  `sts.amazonaws.com`: `access-analyzer:ValidatePolicy` and
  `access-analyzer:CheckNoNewAccess`. Nothing else: a pull request can
  neither sign nor write.
- **`gha-cracha-grants-publish`**, trusted with `sub`
  `repo:bpalermo@4821983/cracha-grants@1424650328:ref:refs/heads/main`: the same Access
  Analyzer actions, `kms:Sign` and `kms:GetPublicKey` on the signing key,
  and
  `s3:PutObject` on `arn:aws:s3:::cracha-grants-988966554486/grants/*`.
- **The signing key**, alias `alias/cracha-grants-signing`
  (`arn:aws:kms:sa-east-1:988966554486:alias/cracha-grants-signing`), an
  asymmetric `ECC_NIST_P256` `SIGN_VERIFY` key. Its key policy lets only the
  publish role `kms:Sign` and denies it to every other principal. Nothing
  else needs the key: the brokers verify with its public key.
- **The bucket** `cracha-grants-988966554486`, private, the bundles under
  the prefix `grants/`.

## Pointing a cluster's broker at it

The chart's `broker.bundle` (see `charts/cracha/values.yaml`), with the
signing key's public key as the verification key:

```yaml
broker:
  bundle:
    source: s3://cracha-grants-988966554486/grants
    verifyKey: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    pollInterval: 60s
```

The PEM is the KMS key's public key: the tf-palermo-dev output `cracha`, or

```bash
aws kms get-public-key --region sa-east-1 --key-id alias/cracha-grants-signing \
  --query PublicKey --output text | base64 -d |
  openssl pkey -pubin -inform DER -outform PEM
```

A signature's `keyId` is the sha256 of that public key, the identity the
broker computes from `verifyKey`, so the broker verifies locally and needs
no KMS permission at all. Its own AWS credentials need only `s3:GetObject`
on `arn:aws:s3:::cracha-grants-988966554486/grants/*` and `s3:ListBucket`
on the bucket for that prefix. Until a bundle has verified the broker is
not ready (`/readyz`), and it keeps the last good version on any failure.

To rotate the signing key, list both public keys in `verifyKey` (the old
PEM and the new one, one after the other) for the overlap, switch the
workflow's `kms-key` to the new key, and drop the old PEM once a bundle
signed with the new key has been published and every broker serves it.
