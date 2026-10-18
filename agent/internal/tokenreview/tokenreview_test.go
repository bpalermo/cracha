package tokenreview

import (
	"context"
	"errors"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// reviewer returns a Kubernetes reviewer whose API server answers every
// TokenReview with status.
func reviewer(status authenticationv1.TokenReviewStatus) *Kubernetes {
	client := fake.NewClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		tr := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		out := tr.DeepCopy()
		out.Status = status
		return true, out, nil
	})
	return NewKubernetes(client)
}

func TestReviewReadsTheBoundPod(t *testing.T) {
	r := reviewer(authenticationv1.TokenReviewStatus{
		Authenticated: true,
		Audiences:     []string{"cracha-agent"},
		User: authenticationv1.UserInfo{
			Username: "system:serviceaccount:apps:api",
			Extra: map[string]authenticationv1.ExtraValue{
				PodNameExtra: {"api-7d9f"},
				PodUIDExtra:  {"uid-1"},
			},
		},
	})
	res, err := r.Review(context.Background(), "tok", "cracha-agent")
	if err != nil {
		t.Fatal(err)
	}
	want := Result{Username: "system:serviceaccount:apps:api", PodName: "api-7d9f", PodUID: "uid-1"}
	if res != want {
		t.Fatalf("Review = %+v, want %+v", res, want)
	}
	if res.Namespace() != "apps" || res.ServiceAccount() != "api" {
		t.Errorf("Namespace/ServiceAccount = %q/%q", res.Namespace(), res.ServiceAccount())
	}
}

func TestReviewRefusals(t *testing.T) {
	for name, status := range map[string]authenticationv1.TokenReviewStatus{
		"not authenticated": {Authenticated: false},
		"error":             {Authenticated: true, Error: "invalid bearer token"},
		"other audience":    {Authenticated: true, Audiences: []string{"cracha-broker"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := reviewer(status).Review(context.Background(), "tok", "cracha-agent"); err == nil {
				t.Fatal("Review accepted the token")
			}
		})
	}
}

func TestReviewUnavailable(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "tokenreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("the server is currently unable to handle the request")
	})
	_, err := NewKubernetes(client).Review(context.Background(), "tok", "cracha-agent")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Review = %v, want ErrUnavailable", err)
	}
}

func TestNamespaceOfANonServiceAccount(t *testing.T) {
	for _, user := range []string{"", "alice", "system:serviceaccount:", "system:serviceaccount:apps", "system:serviceaccount::x"} {
		if ns := (Result{Username: user}).Namespace(); ns != "" {
			t.Errorf("Namespace(%q) = %q", user, ns)
		}
	}
}
