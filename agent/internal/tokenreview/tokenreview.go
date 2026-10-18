// Package tokenreview is the context check of init-mode enrolment
// (docs/design.md, section 7.2): the bound ServiceAccount token the
// cracha-enrol init container presents is verified by the API server for
// the agent's audience, and the pod it is bound to is read from the review's
// extras. It is a check that the request is about the pod the token was
// issued for, not an attestation: that is the issuer's.
package tokenreview

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The TokenReview user extras the API server fills for a token bound to a
// pod.
const (
	PodNameExtra = "authentication.kubernetes.io/pod-name"
	PodUIDExtra  = "authentication.kubernetes.io/pod-uid"
)

// Result is what a successful review says about the token.
type Result struct {
	// Username is the authenticated user: system:serviceaccount:<ns>:<sa>.
	Username string
	// PodName and PodUID are the pod the token is bound to, empty for an
	// unbound token.
	PodName string
	PodUID  string
}

// Namespace is the namespace of the service account the token belongs to,
// from its username, or "" when the user is not a service account.
func (r Result) Namespace() string {
	ns, _, ok := splitServiceAccount(r.Username)
	if !ok {
		return ""
	}
	return ns
}

// ServiceAccount is the name of the service account the token belongs to.
func (r Result) ServiceAccount() string {
	_, sa, _ := splitServiceAccount(r.Username)
	return sa
}

func splitServiceAccount(username string) (ns, sa string, ok bool) {
	const prefix = "system:serviceaccount:"
	rest, found := strings.CutPrefix(username, prefix)
	if !found {
		return "", "", false
	}
	ns, sa, found = strings.Cut(rest, ":")
	if !found || ns == "" || sa == "" {
		return "", "", false
	}
	return ns, sa, true
}

// ErrUnavailable wraps a review that could not be made: the API server did
// not answer, or refused the review itself (RBAC). It is not a verdict on
// the token, and the caller retries.
var ErrUnavailable = errors.New("TokenReview unavailable")

// Reviewer verifies a token for an audience. It returns an error when the
// token is not authenticated for that audience, wrapping ErrUnavailable
// when it could not find out.
type Reviewer interface {
	Review(ctx context.Context, token, audience string) (Result, error)
}

// Kubernetes reviews tokens with the API server's TokenReview.
type Kubernetes struct {
	client kubernetes.Interface
}

// NewKubernetes returns a Reviewer over client. The agent's own service
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
		return Result{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
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
	if names := tr.Status.User.Extra[PodNameExtra]; len(names) == 1 {
		res.PodName = names[0]
	}
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
