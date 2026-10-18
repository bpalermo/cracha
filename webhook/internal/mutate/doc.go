// Package mutate turns a Pod admission request into the JSON Patch that wires
// the pod up to Crachá (docs/design.md, section 7.4). It is pure: everything
// it needs from the cluster comes through the ServiceAccounts and Regions
// interfaces, so the whole decision can be unit tested with a fake clientset.
//
// # What is injected
//
// For a pod whose ServiceAccount carries the annotation
// "cracha.dev/enabled: true", every container and init container gets:
//
//   - the CSI ephemeral inline volume "cracha" (driver csi.cracha.dev,
//     read-only), mounted read-only at /var/run/cracha. Init containers are
//     included because they may call AWS as well, and the token is already
//     there before any of them starts: kubelet publishes the volume before it
//     creates containers (design 7.3).
//   - AWS_CONTAINER_CREDENTIALS_FULL_URI, the broker's credentials endpoint;
//     AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, the token path in that volume;
//     and AWS_REGION.
//
// The pod is marked with the annotation "cracha.dev/injected: true".
// Ephemeral containers are not touched: the API refuses them on CREATE, and
// a debugging container should not get the workload's credentials anyway.
//
// # AWS_REGION
//
// The design says the region comes from the node's topology region, or the
// cluster default. The webhook runs at admission, before the pod is
// scheduled, so the node is not known and the cluster default (the
// --default-region flag) is what it has. The Regions hook overrides the
// default per namespace: the binary serves it from the Namespace annotation
// "cracha.dev/region" (webhook/internal/nsregion), read from an informer's
// cache, so a namespace the cache does not hold yet keeps the default, and
// an annotation that is not an AWS region denies the pod as invalid. A
// container that sets AWS_REGION itself keeps its own value: choosing a
// region is the workload's business, only the credentials are Crachá's.
//
// # Conflicting environment
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
// A pod that already mounts something else at /var/run/cracha, or below it,
// is refused, as is a pod whose volume "cracha" is not the Crachá CSI volume.
//
// # Idempotence
//
// Everything is added only when missing, so a pod that already carries the
// volume, the mounts, the variables and the annotation yields no patch.
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
