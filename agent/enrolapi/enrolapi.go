// Package enrolapi is the contract between cracha-agent and what enrols pods
// with it (docs/design.md, section 7.2): the enrolment label the webhook
// puts on a pod and the agent checks, and the init-mode enrolment endpoint
// with the environment of the cracha-enrol init container the webhook
// injects. The webhook imports it; nothing here imports the agent.
package enrolapi

// Label is the enrolment mark: a pod carrying Label: LabelValue is one the
// agent binds a listener in, whatever asked. The webhook sets it on every
// pod it wires (7.5); the agent refuses a pod without it.
const (
	Label      = "cracha.dev/credentials"
	LabelValue = "true"
)

// Enrolled reports whether labels carry the enrolment mark.
func Enrolled(labels map[string]string) bool {
	return labels[Label] == LabelValue
}

// The init-mode enrolment endpoint, served by the agent on the node's
// address (host network): POST Path with the pod's bound ServiceAccount
// token, issued for Audience, as a bearer. 200 with a Response means the
// listener is bound; 401 the token was refused; 403 the pod is not enrolled,
// has no sandbox on this node or uses the host's network; 429 the pod is
// asking too often; 503 the agent could not answer yet, and the caller
// retries.
const (
	Path     = "/v1/enrol"
	Audience = "cracha-agent"
)

// Response acknowledges an enrolment: the port of the loopback listener now
// bound in the pod's network namespace, which the init container confirms
// it can connect to before it exits.
type Response struct {
	Port int `json:"port"`
}

// Environment of the cracha-enrol init container (`cracha-agent enrol`),
// which the webhook injects: where the agent is, which ports, where the
// token is and how long to keep trying. Each is also a flag of the
// subcommand, for which the variable is the default.
const (
	// EnvHostIP is the node's address, from the downward API (status.hostIP).
	EnvHostIP = "CRACHA_HOST_IP"
	// EnvEnrolPort is the agent's enrolment port (agent.enrolPort).
	EnvEnrolPort = "CRACHA_ENROL_PORT"
	// EnvPort is the loopback listener's port (agent.port), to confirm it
	// accepts a connection from inside the pod.
	EnvPort = "CRACHA_AGENT_PORT"
	// EnvTokenFile is the path of the projected token (audience Audience);
	// DefaultTokenFile when unset.
	EnvTokenFile = "CRACHA_ENROL_TOKEN_FILE"
	// EnvTimeout is how long enrolment is retried before the container
	// exits non-zero (agent.enrolTimeout), as a Go duration.
	EnvTimeout = "CRACHA_ENROL_TIMEOUT"

	// DefaultTokenFile is where the webhook mounts the projected token.
	DefaultTokenFile = "/var/run/secrets/cracha.dev/enrol/token"
	// InitContainerName is the name of the injected init container: the
	// webhook's idempotency key, and what it refuses a pod for carrying
	// unasked.
	InitContainerName = "cracha-enrol"
)
