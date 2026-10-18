// Package tokenreview is the context check of NodePublishVolume
// (docs/design.md, section 7.3, step 2): the kubelet-supplied bound
// ServiceAccount token is verified by the API server and its pod binding must
// match the pod the volume context names. It is a check that the request is
// about the pod kubelet says it is, not an attestation: that is the issuer's.
package tokenreview

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PodUIDExtra is the TokenReview user extra the API server fills with the
// UID of the pod a bound token was issued for.
const PodUIDExtra = "authentication.kubernetes.io/pod-uid"

// Result is what a successful review says about the token.
type Result struct {
	// Username is the authenticated user: system:serviceaccount:<ns>:<sa>.
	Username string
	// PodUID is the pod the token is bound to, empty for an unbound token.
	PodUID string
}

// Reviewer verifies a token for an audience. It returns an error when the
// token is not authenticated for that audience.
type Reviewer interface {
	Review(ctx context.Context, token, audience string) (Result, error)
}

// Binding is the pod a token must be bound to.
type Binding struct {
	Namespace      string
	ServiceAccount string
	PodUID         string
}

// Username is the Kubernetes username of the binding's service account.
func (b Binding) Username() string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", b.Namespace, b.ServiceAccount)
}

// Check reviews token for audience with r and requires it to be bound to
// exactly want: the service account's username and the pod UID.
func Check(ctx context.Context, r Reviewer, token, audience string, want Binding) error {
	if token == "" {
		return errors.New("no service account token for audience " + audience)
	}
	res, err := r.Review(ctx, token, audience)
	if err != nil {
		return err
	}
	if res.Username != want.Username() {
		return fmt.Errorf("the service account token belongs to %q, not to %q", res.Username, want.Username())
	}
	if res.PodUID == "" {
		return errors.New("the service account token is not bound to a pod")
	}
	if res.PodUID != want.PodUID {
		return fmt.Errorf("the service account token is bound to pod %s, not to %s", res.PodUID, want.PodUID)
	}
	return nil
}

// Kubernetes reviews tokens with the API server's TokenReview.
type Kubernetes struct {
	client kubernetes.Interface
}

// NewKubernetes returns a Reviewer over client. The plugin's own service
// account needs `create` on tokenreviews.authentication.k8s.io.
func NewKubernetes(client kubernetes.Interface) *Kubernetes {
	return &Kubernetes{client: client}
}

// Review implements Reviewer.
func (k *Kubernetes) Review(ctx context.Context, token, audience string) (Result, error) {
	tr := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{audience}},
	}
	tr, err := k.client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("TokenReview: %w", err)
	}
	if tr.Status.Error != "" {
		return Result{}, fmt.Errorf("TokenReview: %s", tr.Status.Error)
	}
	if !tr.Status.Authenticated {
		return Result{}, errors.New("TokenReview: the token is not authenticated")
	}
	if !slices.Contains(tr.Status.Audiences, audience) {
		return Result{}, fmt.Errorf("TokenReview: the token is not for audience %q (got %q)", audience, tr.Status.Audiences)
	}
	res := Result{Username: tr.Status.User.Username}
	if uids := tr.Status.User.Extra[PodUIDExtra]; len(uids) == 1 {
		res.PodUID = uids[0]
	}
	return res, nil
}

// Fake is a Reviewer for tests, answering from Fn and counting calls.
type Fake struct {
	Fn func(token, audience string) (Result, error)

	mu    sync.Mutex
	calls int
}

// Review implements Reviewer.
func (f *Fake) Review(_ context.Context, token, audience string) (Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.Fn == nil {
		return Result{}, errors.New("fake reviewer refuses everything")
	}
	return f.Fn(token, audience)
}

// Calls returns how many reviews were asked.
func (f *Fake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
