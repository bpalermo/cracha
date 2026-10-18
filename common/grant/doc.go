// Package grant is the grant bundle model and its compiler (docs/design.md,
// section 6.2): it loads Grant, Assignment and Service documents and
// session policy templates from a Git checkout, validates them, renders the
// templates, runs the lints of the grant-compiler pipeline, compiles the
// signed bundle the broker consumes, and signs and publishes it. The same
// tree is the source of truth of the authorization store: its Assignments
// and Services compile into the assignments document published beside the
// bundle, which the broker's static backend reads, and the reconciler
// (reconciler/) turns them into SpiceDB relationships, both through
// ResolveAssignments.
//
// # Source tree
//
// A grant source directory holds YAML documents, one object per file, found
// by walking the tree for *.yaml and *.yml files, and session policy
// templates under a templates/ directory at its root:
//
//	grants/payments-ledger-rw.yaml      kind: Grant
//	assignments/payments.yaml           kind: Assignment
//	services/payments-api.yaml          kind: Service
//	templates/dynamo-table-rw.json      a session policy template
//
// Unknown fields are rejected, so a typo in a field name fails the load
// rather than silently widening or narrowing a grant. Names (of grants,
// assignments, services, teams and templates) are DNS labels: lowercase
// letters, digits and dashes, at most 63 characters, so they are safe as
// file names, session tag values, metrics labels and authorization-store
// object IDs.
//
// # Grant
//
// A Grant is the document of design section 6.2:
//
//	kind: Grant
//	metadata:
//	  name: payments-ledger-rw
//	spec:
//	  account: "111122223333"
//	  baseRole: arn:aws:iam::111122223333:role/broker/shape-dynamo-rw
//	  sessionPolicy:
//	    template: dynamo-table-rw
//	    params: { tables: [ledger, ledger-outbox] }
//	  managedPolicyArns: []
//	  sessionTags: { team: payments }
//	  duration: 3600
//	  envelope:
//	    - arn:aws:dynamodb:*:111122223333:table/payments-*
//
// A grant carries a session policy, managed policy ARNs, or both; one with
// neither would hand out the whole shape role and is rejected.
//
// # Assignment
//
// An Assignment records, in Git, which grants a workload holds, so that the
// composition lint (pipeline step 5) can check the union of a subject's
// grants before the authorization store is written. It is this package's
// definition; the design leaves the Git shape of assignments open.
//
//	kind: Assignment
//	metadata:
//	  name: payments-ledger
//	spec:
//	  subject: prod/payments/ledger        # authz subject encoding (design 4.3)
//	  grants: [payments-ledger-rw, payments-outbox-r]
//	  expiresAt: "2026-12-31T00:00:00Z"    # optional, RFC 3339
//	  clusters: [prod-us-east-1]           # optional; absent means every cluster
//	  suspended: true                      # optional; the subject holds nothing while set
//
// The subject is the authorization subject encoding of design section 4.3,
// <td-short>/<ns>/<sa>, produced by the shared encoding library; this package
// treats it as an opaque string. A subject may appear in several Assignments
// (a permanent one and a temporary one, say); the composition lint unions
// them per cluster. An Assignment whose expiresAt is in the past is left out
// of the composition and reported. A suspended Assignment may name no
// grants: it is then only the suspension, which the authorization store
// enforces (the subject holds nothing, through any source, until it is
// cleared); the composition lint still checks the subject's union, so that
// lifting the suspension cannot surprise.
//
// # Service
//
// A Service groups the workloads of one team that share grants, the way the
// authorization store's service and team do (design 6.4): every member
// holds the service's grants and carries its name and team as session tags.
//
//	kind: Service
//	metadata:
//	  name: payments-api
//	spec:
//	  team: payments
//	  members:                             # authz subject encodings
//	    - prod/payments/ledger
//	    - prod/payments/api
//	  grants:                              # each bounded like an Assignment
//	    - name: payments-ledger-rw
//	    - name: payments-outbox-r
//	      expiresAt: "2026-12-31T00:00:00Z"
//	      clusters: [prod-us-east-1]
//
// A workload is a member of at most one service across the tree. The
// composition lint sees a subject's grants from its Assignments and from
// its service together.
//
// # Session policy templates
//
// A template is a JSON file, named after it (templates/<name>.json), with
// its declared parameters and the policy document they are substituted
// into:
//
//	{
//	  "params": {
//	    "tables": { "type": "list", "description": "table names" },
//	    "region": { "type": "string", "default": "*" }
//	  },
//	  "policy": {
//	    "Version": "2012-10-17",
//	    "Statement": [ {
//	      "Effect": "Allow",
//	      "Action": [ "dynamodb:GetItem", "dynamodb:PutItem" ],
//	      "Resource": [ "arn:aws:dynamodb:${region}:${account}:table/${tables}" ]
//	    } ]
//	  }
//	}
//
// The template language is parameter substitution and nothing else: no
// code, no conditionals, no access to anything but the declared parameters.
// Rendering walks the policy and replaces ${name} inside string values
// (never keys) with the parameter's value. A parameter is a string or a list
// of strings; "account" is implicit and always the grant's account. A string
// that references a list expands to one string per element (the cartesian
// product when it references several lists): spliced in place when the
// string is an array element, and turned into an array when it is an object
// value. "$${" is a literal "${". Rendering fails on a reference to an
// undeclared parameter, a declared parameter the grant does not supply and
// that has no default, a parameter the grant supplies that the template does
// not declare, a type mismatch, or an empty list. Values are substituted
// into the decoded document, so a value can never break out of its JSON
// string. The rendered policy is the minified JSON of the result, with
// object keys sorted.
//
// # Bundle
//
// Compile produces the bundle document the broker polls:
//
//	{
//	  "version": "<content hash, or the git commit when given>",
//	  "generatedAt": "<RFC 3339>",
//	  "grants": [ { "name", "account", "baseRole", "sessionPolicy",
//	                "managedPolicyArns", "sessionTags", "duration",
//	                "envelope" } ]
//	}
//
// Its bytes are canonical: object keys sorted, grants sorted by name, two
// space indentation and a trailing newline, so the same sources compile to
// the same bytes.
//
// # Assignments
//
// Compile also produces, under the same version and generatedAt, the
// assignments document: who holds which grant, as the tree's Services and
// Assignments say (ResolveAssignments), for the broker's static
// authorization backend to read from the publication instead of a file of
// each cluster's:
//
//	{
//	  "version", "generatedAt",
//	  "services":  [ { "name", "team", "members", "grants": [ { "name", "expiresAt"?, "clusters"? } ] } ],
//	  "workloads": [ { "subject", "suspended", "grants": [ { "name", "expiresAt"?, "clusters"? } ] } ]
//	}
//
// A workload is every Assignment of one subject, merged: suspended when any
// is, and each grant once, with the union of the bounds the Assignments give
// it, the way the reconciler writes the same tree to SpiceDB (the mapping is
// one function, ResolveAssignments). Its bytes are canonical as the
// bundle's are. The version, when none is given, is the SHA-256 of the
// grants and of the services and workloads together, so a change to who
// holds a grant alone is a new version.
//
// # Signature envelope
//
// A signature is a small JSON document kept next to the document it signs
// (bundle.json.sig, assignments.json.sig), detached from it:
//
//	{
//	  "version": 1,
//	  "algorithm": "ECDSA_SHA_256",
//	  "keyId": "<local: sha256:<hex> of the public key's DER; KMS: the key ARN>",
//	  "digest": "sha256:<hex of the document's bytes>",
//	  "signature": "<base64 of the ASN.1 DER ECDSA signature over the digest>"
//	}
//
// The signature covers the exact bytes of the published file. The
// local signer uses an ECDSA P-256 key; the KMS signer uses an asymmetric
// ECC_NIST_P256 signing key through kms:Sign, and the two produce
// interchangeable signatures, so a bundle signed by KMS verifies offline
// with the key's exported public key. Cosign signing (design 6.2 step 6) is
// a later addition.
//
// A reader may trust several keys (KeyRing): the envelope's keyId selects
// the one that verifies, which is how a signing key is rotated.
//
// # Publication layout
//
// A publisher writes, under its root (a directory or an S3 prefix):
//
//	bundles/<version>/bundle.json
//	bundles/<version>/bundle.json.sig
//	bundles/<version>/assignments.json       optional: published with the bundle
//	bundles/<version>/assignments.json.sig
//	latest                         {"version","bundle","signature"}
//
// The versioned keys are written first and the latest pointer last, so a
// reader that follows the pointer always finds a complete version. The
// pointer does not name the assignments: a reader finds them where the
// layout puts a version's, so that a reader which predates them, and
// decodes the pointer strictly, keeps working. This package's ParseLatest
// ignores fields it does not know, so the next additive change need not
// wait for that.
package grant
