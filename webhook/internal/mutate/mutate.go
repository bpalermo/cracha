package mutate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Labels and annotations read and written by the webhook.
const (
	// AnnotationEnabled on a ServiceAccount, with the value "true", opts its
	// pods in.
	AnnotationEnabled = "cracha.dev/enabled"
	// LabelCredentials on a pod, with the value "true", is the enrolment
	// mark the agent checks before it binds a listener (design 7.2), and the
	// webhook's idempotency key: a pod that carries it is left unchanged.
	LabelCredentials = "cracha.dev/credentials"
	// AnnotationStrippedEnv records, as a JSON list of StrippedEnv, the
	// variables the strip policy removed from a pod.
	AnnotationStrippedEnv = "cracha.dev/stripped-env"
	// AnnotationRegion on a Namespace overrides AWS_REGION for its pods,
	// served through the Regions hook (webhook/internal/nsregion).
	AnnotationRegion = "cracha.dev/region"
)

// The loopback endpoint (design 7.1): the agent's listener inside the pod's
// network namespace, serving the broker's credentials path (design 6.5).
const (
	LoopbackHost    = "127.0.0.1"
	CredentialsPath = "/v1/credentials"
)

// The variables the webhook sets in every container.
const (
	EnvCredentialsURI = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
	EnvRegion         = "AWS_REGION"
)

// Enrolment in the init mode (design 7.2): the init container, its token
// volume and the variables it reads.
const (
	// EnrolContainerName is the init container the webhook injects first in
	// the list; a pod that carries one of this name without the label is
	// refused.
	EnrolContainerName = "cracha-enrol"
	// EnrolVolumeName is the projected token volume, mounted into that
	// container only.
	EnrolVolumeName = "cracha-enrol"
	// EnrolTokenAudience is the audience of the projected token, which the
	// agent's TokenReview checks.
	EnrolTokenAudience = "cracha-agent"
	// EnrolTokenExpirationSeconds is the shortest lifetime the API allows
	// for a projected token.
	EnrolTokenExpirationSeconds = 600
	// EnrolTokenDir is where the volume is mounted in the init container and
	// EnrolTokenPath the token in it: the path the agent's `enrol` reads,
	// also handed to it as CRACHA_ENROL_TOKEN_FILE.
	EnrolTokenDir  = "/var/run/secrets/cracha.dev/enrol"
	EnrolTokenFile = "token"
	EnrolTokenPath = EnrolTokenDir + "/" + EnrolTokenFile
	// EnrolArg is the agent image's subcommand the init container runs; the
	// image's entrypoint is the agent binary.
	EnrolArg = "enrol"

	// The init container's environment: the node's address from the
	// downward API, the agent's enrolment port, how long to retry, and the
	// token's path.
	EnvNodeIP         = "NODE_IP"
	EnvEnrolPort      = "CRACHA_ENROL_PORT"
	EnvEnrolTimeout   = "CRACHA_ENROL_TIMEOUT"
	EnvEnrolTokenFile = "CRACHA_ENROL_TOKEN_FILE"

	// enrolUID is distroless's nonroot user, which the agent image runs as.
	enrolUID int64 = 65532
)

// ConflictPolicy says what happens to a pod that sets a conflicting variable.
type ConflictPolicy int

const (
	// Reject denies the admission, naming each container and variable.
	Reject ConflictPolicy = iota
	// Strip removes the variables and records them in AnnotationStrippedEnv.
	Strip
)

// String implements flag.Value.
func (p ConflictPolicy) String() string {
	switch p {
	case Reject:
		return "reject"
	case Strip:
		return "strip"
	}
	return fmt.Sprintf("ConflictPolicy(%d)", int(p))
}

// Set implements flag.Value.
func (p *ConflictPolicy) Set(s string) error {
	switch s {
	case "reject":
		*p = Reject
	case "strip":
		*p = Strip
	default:
		return fmt.Errorf("unknown conflicting-env policy %q: want reject or strip", s)
	}
	return nil
}

// EnrolMode is how a pod's listener gets bound (design 7.2), which decides
// what the webhook injects beyond the variables and the label.
type EnrolMode int

const (
	// EnrolInit injects the cracha-enrol init container and its token.
	EnrolInit EnrolMode = iota
	// EnrolCNI injects nothing more: the CNI plugin enrols the pod.
	EnrolCNI
)

// String implements flag.Value.
func (m EnrolMode) String() string {
	switch m {
	case EnrolInit:
		return "init"
	case EnrolCNI:
		return "cni"
	}
	return fmt.Sprintf("EnrolMode(%d)", int(m))
}

// Set implements flag.Value.
func (m *EnrolMode) Set(s string) error {
	switch s {
	case "init":
		*m = EnrolInit
	case "cni":
		*m = EnrolCNI
	default:
		return fmt.Errorf("unknown enrolment mode %q: want init or cni", s)
	}
	return nil
}

// Config is what the mutator needs to know about its deployment.
type Config struct {
	// AgentPort is the port of the agent's loopback listener in every pod
	// (agent.port), the one AWS_CONTAINER_CREDENTIALS_FULL_URI names.
	AgentPort int
	// DefaultRegion is the value of AWS_REGION unless a Regions hook or the
	// container itself says otherwise.
	DefaultRegion string
	// ConflictingEnv is the policy for variables the pod set itself.
	ConflictingEnv ConflictPolicy
	// Enrol is the enrolment mode (agent.enrol).
	Enrol EnrolMode
	// AgentImage is the agent image the init container runs, by digest
	// (agent.image); required in the init mode.
	AgentImage string
	// EnrolPort is the port of the agent's enrolment endpoint on the node's
	// address (agent.enrolPort); required in the init mode.
	EnrolPort int
	// EnrolTimeout is how long the init container retries enrolment before
	// it fails (agent.enrolTimeout); required in the init mode.
	EnrolTimeout time.Duration
}

// CredentialsURI is the value of AWS_CONTAINER_CREDENTIALS_FULL_URI.
func (c Config) CredentialsURI() string {
	return "http://" + LoopbackHost + ":" + strconv.Itoa(c.AgentPort) + CredentialsPath
}

// validate reports the first thing missing or out of range.
func (c Config) validate() error {
	if !validPort(c.AgentPort) {
		return fmt.Errorf("agent port %d is not a TCP port", c.AgentPort)
	}
	if c.DefaultRegion == "" {
		return errors.New("default region must be set")
	}
	if c.Enrol != EnrolInit {
		return nil
	}
	if c.AgentImage == "" {
		return errors.New("the init enrolment mode needs the agent image")
	}
	if !validPort(c.EnrolPort) {
		return fmt.Errorf("enrolment port %d is not a TCP port", c.EnrolPort)
	}
	if c.EnrolTimeout <= 0 {
		return fmt.Errorf("enrolment timeout %s must be positive", c.EnrolTimeout)
	}
	return nil
}

func validPort(p int) bool { return p > 0 && p <= 65535 }

// ServiceAccounts looks ServiceAccounts up. The returned object is shared
// with the caller's cache and must not be modified.
type ServiceAccounts interface {
	Get(ctx context.Context, namespace, name string) (*corev1.ServiceAccount, error)
}

// Regions is the hook for a per-namespace AWS_REGION override. An empty
// region means no override; an error denies the admission, as invalid when
// it is an InvalidRegionError and as unavailable otherwise.
type Regions interface {
	Region(ctx context.Context, namespace string) (string, error)
}

// InvalidRegionError is what a Regions hook returns for an override that is
// not an AWS region: the pod is denied as invalid, naming the annotation,
// rather than as a lookup failure.
type InvalidRegionError struct {
	Namespace string
	Value     string
}

func (e *InvalidRegionError) Error() string {
	return fmt.Sprintf("annotation %s of namespace %s is %q, not an AWS region such as us-east-1",
		AnnotationRegion, e.Namespace, e.Value)
}

// regionPattern is the shape of every AWS region: a two-letter partition
// prefix, one or more words and a number (us-east-1, eu-central-2,
// ap-southeast-3, us-gov-west-1, cn-north-1, il-central-1).
var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// IsRegion reports whether s is shaped like an AWS region. It does not know
// which regions exist: the SDK's own validation of AWS_REGION is as loose,
// and a new region must not need a webhook release.
func IsRegion(s string) bool {
	return regionPattern.MatchString(s)
}

// Mutator admits Pod CREATE requests.
type Mutator struct {
	cfg     Config
	sas     ServiceAccounts
	regions Regions
}

// Option configures a Mutator.
type Option func(*Mutator)

// WithRegions installs the per-namespace region hook.
func WithRegions(r Regions) Option {
	return func(m *Mutator) { m.regions = r }
}

// New returns a Mutator. The agent port and the default region must be set,
// and in the init mode the agent image, the enrolment port and the timeout.
func New(cfg Config, sas ServiceAccounts, opts ...Option) (*Mutator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if sas == nil {
		return nil, errors.New("service account lookup must be set")
	}
	m := &Mutator{cfg: cfg, sas: sas}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// Config returns the configuration in effect.
func (m *Mutator) Config() Config { return m.cfg }

// Operation is one RFC 6902 JSON Patch operation.
type Operation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// StrippedEnv is one entry of AnnotationStrippedEnv.
type StrippedEnv struct {
	Container string `json:"container"`
	Name      string `json:"name"`
}

// Conflicts reports whether a variable of that name, set by the pod, would
// get in the way of the container credentials provider.
func Conflicts(name string) bool {
	switch name {
	case "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE":
		return true
	}
	for _, prefix := range []string{
		"AWS_WEB_IDENTITY_", "AWS_ROLE_",
		"AWS_CONTAINER_CREDENTIALS_", "AWS_CONTAINER_AUTHORIZATION_",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Admit decides a request. The response always carries the request's UID.
// It allows anything that is not a Pod CREATE unchanged, denies on any
// failure to decide, and otherwise answers with the patch, or without one
// when the pod needs nothing.
func (m *Mutator) Admit(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if !isPodCreate(req) {
		return allowed(req.UID)
	}
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denied(req.UID, http.StatusBadRequest, metav1.StatusReasonBadRequest,
			fmt.Sprintf("cracha: decoding the pod: %v", err))
	}
	namespace, saName := subject(req, &pod)
	sa, deny := m.serviceAccount(ctx, req.UID, namespace, saName)
	if deny != nil {
		return deny
	}
	if sa.Annotations[AnnotationEnabled] != "true" {
		return allowed(req.UID)
	}
	if pod.Labels[LabelCredentials] == "true" {
		// Already wired: the label is the idempotency key.
		return allowed(req.UID)
	}
	region, deny := m.region(ctx, req.UID, namespace)
	if deny != nil {
		return deny
	}
	p := planner{cfg: m.cfg, region: region}
	p.plan(&pod)
	return p.response(req.UID)
}

// isPodCreate reports whether req is the creation of a core/v1 Pod itself,
// the one operation the webhook acts on.
func isPodCreate(req *admissionv1.AdmissionRequest) bool {
	return req.Operation == admissionv1.Create && req.SubResource == "" &&
		req.Kind.Group == "" && req.Kind.Version == "v1" && req.Kind.Kind == "Pod"
}

// subject names the ServiceAccount the pod runs as: in the request's
// namespace, or the pod's own when the request names none, and the pod's
// service account name, default when it sets none.
func subject(req *admissionv1.AdmissionRequest, pod *corev1.Pod) (namespace, name string) {
	namespace = req.Namespace
	if namespace == "" {
		namespace = pod.Namespace
	}
	name = pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	return namespace, name
}

// serviceAccount looks the ServiceAccount up, or returns the denial: a
// missing one is the pod's fault, any other failure is the API server's.
func (m *Mutator) serviceAccount(ctx context.Context, uid types.UID, namespace, name string) (*corev1.ServiceAccount, *admissionv1.AdmissionResponse) {
	sa, err := m.sas.Get(ctx, namespace, name)
	if err == nil {
		return sa, nil
	}
	if apierrors.IsNotFound(err) {
		return nil, denied(uid, http.StatusUnprocessableEntity, metav1.StatusReasonInvalid,
			fmt.Sprintf("cracha: service account %s/%s not found", namespace, name))
	}
	return nil, denied(uid, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable,
		fmt.Sprintf("cracha: looking up service account %s/%s: %v", namespace, name, err))
}

// region is the AWS_REGION to inject in namespace: the Regions hook's
// override when there is one, otherwise the default. A failing hook denies:
// an override that is not a region as invalid, anything else as unavailable.
func (m *Mutator) region(ctx context.Context, uid types.UID, namespace string) (string, *admissionv1.AdmissionResponse) {
	if m.regions == nil {
		return m.cfg.DefaultRegion, nil
	}
	override, err := m.regions.Region(ctx, namespace)
	var invalid *InvalidRegionError
	if errors.As(err, &invalid) {
		return "", denied(uid, http.StatusUnprocessableEntity, metav1.StatusReasonInvalid, "cracha: "+err.Error())
	}
	if err != nil {
		return "", denied(uid, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable,
			fmt.Sprintf("cracha: resolving the region of namespace %s: %v", namespace, err))
	}
	if override == "" {
		return m.cfg.DefaultRegion, nil
	}
	return override, nil
}

// response turns the plan into the decision: a denial naming every problem,
// an unchanged admission when the pod needs nothing, or the patch with the
// warnings collected along the way.
func (p *planner) response(uid types.UID) *admissionv1.AdmissionResponse {
	if len(p.problems) > 0 {
		return denied(uid, http.StatusUnprocessableEntity, metav1.StatusReasonInvalid,
			"cracha: "+strings.Join(p.problems, "; "))
	}
	if len(p.ops) == 0 {
		return allowed(uid)
	}
	patch, err := json.Marshal(p.ops)
	if err != nil {
		return denied(uid, http.StatusInternalServerError, metav1.StatusReasonInternalError,
			fmt.Sprintf("cracha: encoding the patch: %v", err))
	}
	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:       uid,
		Allowed:   true,
		PatchType: &patchType,
		Patch:     patch,
		Warnings:  p.warnings,
	}
}

func allowed(uid types.UID) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{UID: uid, Allowed: true}
}

func denied(uid types.UID, code int32, reason metav1.StatusReason, message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    code,
			Reason:  reason,
			Message: message,
		},
	}
}
