// Package mutate turns a Pod admission request into the JSON Patch that wires
// the pod up to Crachá (docs/design.md, section 7.5). It is pure: everything
// it needs from the cluster comes through the ServiceAccounts and Regions
// interfaces, so the whole decision can be unit tested with a fake clientset.
//
// # What is injected
//
// For a pod whose ServiceAccount carries the annotation
// "cracha.dev/enabled: true", every container and init container gets:
//
//   - AWS_CONTAINER_CREDENTIALS_FULL_URI, the loopback endpoint the node agent
//     binds inside the pod's network namespace (design 7.1):
//     http://127.0.0.1:<agent port>/v1/credentials. Init containers are
//     included because they may call AWS as well, and the listener is there
//     before any of them starts (design 7.2).
//   - AWS_REGION.
//   - AWS_METADATA_SERVICE_TIMEOUT and AWS_METADATA_SERVICE_NUM_ATTEMPTS
//     (Config.SDKTimeoutSeconds, Config.SDKAttempts; zero leaves one out),
//     the per-attempt timeout and the attempts of the credential fetch for
//     the SDKs that read them for the container provider (design 7.7: of
//     the first-party SDKs, PHP), so that one cold issuance does not
//     outlast the SDK's patience. A container that sets either keeps its
//     own, as with AWS_REGION.
//
// and the pod gets the label "cracha.dev/credentials: true", the enrolment
// mark the agent checks before it binds anything (design 7.2).
//
// In the init enrolment mode (Config.Enrol) the pod also gets what enrolment
// needs: the init container "cracha-enrol", first in the list so that it
// holds every other init container too, running `enrol` from the agent image
// against the node's address (CRACHA_HOST_IP, from status.hostIP) and the
// agent's enrolment port (CRACHA_ENROL_PORT) for at most CRACHA_ENROL_TIMEOUT,
// then confirming the listener on CRACHA_AGENT_PORT accepts a connection; and
// the projected ServiceAccount token it authenticates with (audience
// "cracha-agent", the shortest lifetime the API allows, bound to the pod), in
// the volume "cracha-enrol" mounted into that container only, at
// EnrolTokenPath (CRACHA_ENROL_TOKEN_FILE). The names are agent/enrolapi's,
// the agent's definition of the contract. The container runs under the
// restricted Pod Security standard: non-root, no privileges, no writable
// filesystem, no capabilities. The pattern is aether's identity-gate init
// container; the label, not the container, is the idempotency key. In the
// cni mode nothing enters the pod but the variables and the label.
//
// There is no token file, no AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, no CA
// bundle and no volume for the app containers: the pod holds nothing.
// Ephemeral containers are not touched: the API refuses them on CREATE, and
// a debugging container should not get the workload's credentials anyway.
//
// # AWS_REGION
//
// The webhook runs at admission, before the pod is scheduled, so the node's
// topology region is not known and the cluster default (the --default-region
// flag) is what it has. The Regions hook overrides the default per
// namespace: the binary serves it from the Namespace annotation
// "cracha.dev/region" (webhook/internal/nsregion), read from an informer's
// cache, so a namespace the cache does not hold yet keeps the default, and
// an annotation that is not an AWS region denies the pod as invalid. A
// container that sets AWS_REGION itself keeps its own value: choosing a
// region is the workload's business, only the credentials are Crachá's.
//
// # Refusals
//
// A pod with hostNetwork has no network namespace of its own, so a loopback
// listener there would serve every process on the node: it is refused
// (design 7.1). A pod that already carries an init container or a volume
// named "cracha-enrol" without the label is refused too: the webhook did not
// put it there, and it would be taken for the webhook's.
//
// The AWS SDK's default credential chain tries static keys, the shared
// config and credentials files, web identity and role settings before the
// container provider, so any of these set by the pod would silently win over
// Crachá or redirect the container provider elsewhere. The webhook therefore
// refuses a pod that sets AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// AWS_SESSION_TOKEN, AWS_CONFIG_FILE, AWS_SHARED_CREDENTIALS_FILE or any
// AWS_WEB_IDENTITY_*, AWS_ROLE_*, AWS_CONTAINER_CREDENTIALS_* or
// AWS_CONTAINER_AUTHORIZATION_* variable, whether the value is literal or
// comes from valueFrom. With the strip policy it removes them instead,
// records what it removed in the annotation "cracha.dev/stripped-env" (a
// JSON list of container and variable name) and returns a warning per
// variable. Variables that reach the container through envFrom are not
// visible at admission and are not checked.
//
// # Idempotence
//
// The label is the idempotency key: a pod that already carries
// "cracha.dev/credentials: true" is left unchanged, whatever else it
// carries, so a pod the webhook has already wired (or one that was wired by
// hand, which the agent treats the same) yields no patch.
//
// # Failing closed
//
// An error looking up the ServiceAccount denies the request with the reason:
// the webhook never guesses. A pod whose ServiceAccount is not annotated is
// allowed unchanged, since Crachá has nothing to do with it. Requests that
// are not a Pod CREATE are allowed unchanged too: there is nothing to inject
// into them, and a pod's spec is immutable after creation. An HTTP-level
// failure of the webhook is handled by the apiserver according to the
// webhook configuration's failurePolicy, which must be Fail for the same
// guarantee to hold there.
package mutate
