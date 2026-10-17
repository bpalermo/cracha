package mutate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Annotations read and written by the webhook.
const (
	// AnnotationEnabled on a ServiceAccount, with the value "true", opts its
	// pods in.
	AnnotationEnabled = "cracha.dev/enabled"
	// AnnotationInjected marks a pod the webhook has wired up.
	AnnotationInjected = "cracha.dev/injected"
	// AnnotationStrippedEnv records, as a JSON list of StrippedEnv, the
	// variables the strip policy removed from a pod.
	AnnotationStrippedEnv = "cracha.dev/stripped-env"
	// AnnotationRegion on a Namespace is the intended key for a per-namespace
	// AWS_REGION override, served through the Regions hook.
	AnnotationRegion = "cracha.dev/region"
)

// The volume and its mount (design 7.1 and 7.2).
const (
	VolumeName = "cracha"
	Driver     = "csi.cracha.dev"
	MountPath  = "/var/run/cracha"
	TokenPath  = MountPath + "/token"
)

// The broker's credentials endpoint (design 6.5), appended to a broker URL
// that does not already end in it.
const CredentialsPath = "/v1/credentials"

// The variables the webhook sets.
const (
	EnvCredentialsURI = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
	EnvTokenFile      = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
	EnvRegion         = "AWS_REGION"
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

// Config is what the mutator needs to know about its deployment.
type Config struct {
	// BrokerURL is the value of AWS_CONTAINER_CREDENTIALS_FULL_URI. Build it
	// with BrokerURL to get the scheme and path checked.
	BrokerURL string
	// DefaultRegion is the value of AWS_REGION unless a Regions hook or the
	// container itself says otherwise.
	DefaultRegion string
	// ConflictingEnv is the policy for variables the pod set itself.
	ConflictingEnv ConflictPolicy
}

// BrokerURL validates a broker URL for AWS_CONTAINER_CREDENTIALS_FULL_URI
// and appends CredentialsPath unless the path already ends with it. The SDK
// only accepts https for a non-loopback host, so https is required.
func BrokerURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("broker URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("broker URL %q: scheme must be https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("broker URL %q: missing host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("broker URL %q: must carry no user, query or fragment", raw)
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p != "" {
		p = path.Clean(p)
	}
	if !strings.HasSuffix(p, CredentialsPath) {
		p += CredentialsPath
	}
	u.Path = p
	u.RawPath = ""
	return u.String(), nil
}

// ServiceAccounts looks ServiceAccounts up. The returned object is shared
// with the caller's cache and must not be modified.
type ServiceAccounts interface {
	Get(ctx context.Context, namespace, name string) (*corev1.ServiceAccount, error)
}

// Regions is the hook for a per-namespace AWS_REGION override. An empty
// region means no override; an error denies the admission.
type Regions interface {
	Region(ctx context.Context, namespace string) (string, error)
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

// New returns a Mutator. The broker URL is validated as BrokerURL does, and
// the default region must be set: the webhook has no node to take it from.
func New(cfg Config, sas ServiceAccounts, opts ...Option) (*Mutator, error) {
	u, err := BrokerURL(cfg.BrokerURL)
	if err != nil {
		return nil, err
	}
	cfg.BrokerURL = u
	if cfg.DefaultRegion == "" {
		return nil, errors.New("default region must be set")
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

// Config returns the configuration in effect, with the broker URL as it is
// injected.
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
	if req.Operation != admissionv1.Create || req.SubResource != "" ||
		req.Kind.Group != "" || req.Kind.Version != "v1" || req.Kind.Kind != "Pod" {
		return allowed(req.UID)
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denied(req.UID, http.StatusBadRequest, metav1.StatusReasonBadRequest,
			fmt.Sprintf("cracha: decoding the pod: %v", err))
	}

	namespace := req.Namespace
	if namespace == "" {
		namespace = pod.Namespace
	}
	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	sa, err := m.sas.Get(ctx, namespace, saName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return denied(req.UID, http.StatusUnprocessableEntity, metav1.StatusReasonInvalid,
				fmt.Sprintf("cracha: service account %s/%s not found", namespace, saName))
		}
		return denied(req.UID, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable,
			fmt.Sprintf("cracha: looking up service account %s/%s: %v", namespace, saName, err))
	}
	if sa.Annotations[AnnotationEnabled] != "true" {
		return allowed(req.UID)
	}

	region := m.cfg.DefaultRegion
	if m.regions != nil {
		override, err := m.regions.Region(ctx, namespace)
		if err != nil {
			return denied(req.UID, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable,
				fmt.Sprintf("cracha: resolving the region of namespace %s: %v", namespace, err))
		}
		if override != "" {
			region = override
		}
	}

	p := planner{cfg: m.cfg, region: region}
	p.plan(&pod)
	if len(p.problems) > 0 {
		return denied(req.UID, http.StatusUnprocessableEntity, metav1.StatusReasonInvalid,
			"cracha: "+strings.Join(p.problems, "; "))
	}
	if len(p.ops) == 0 {
		return allowed(req.UID)
	}
	patch, err := json.Marshal(p.ops)
	if err != nil {
		return denied(req.UID, http.StatusInternalServerError, metav1.StatusReasonInternalError,
			fmt.Sprintf("cracha: encoding the patch: %v", err))
	}
	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:       req.UID,
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
