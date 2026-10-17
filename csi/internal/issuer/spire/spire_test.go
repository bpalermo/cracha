package spire

import (
	"context"
	"net"
	"testing"
	"time"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/bpalermo/cracha/csi/internal/issuer"
	"github.com/bpalermo/cracha/csi/internal/jwttest"
)

// fakeBroker is a Broker API server answering FetchJWTSVID from a function.
type fakeBroker struct {
	brokerpb.UnimplementedAPIServer
	fetch func(ctx context.Context, req *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error)
}

func (f *fakeBroker) FetchJWTSVID(ctx context.Context, req *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
	return f.fetch(ctx, req)
}

// newTestIssuer serves fb over an in-memory connection and returns an Issuer
// on it. The transport is plain: what is under test is the request, the
// metadata and the error classification, not mTLS.
func newTestIssuer(t *testing.T, fb *fakeBroker) *Issuer {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	brokerpb.RegisterAPIServer(srv, fb)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newWithClient(brokerpb.NewAPIClient(conn), nil)
}

var ref = issuer.PodRef{Namespace: "team-a", Name: "web-0", UID: "7e3c1a2b-0000-4000-8000-000000000001"}

func TestFetchJWTSVID(t *testing.T) {
	exp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	token := jwttest.Mint(jwttest.Claims{
		Subject:  "spiffe://example.org/ns/team-a/sa/web",
		Audience: []string{"cracha-broker"},
		IssuedAt: time.Now(),
		Expiry:   exp,
	})

	var got *brokerpb.FetchJWTSVIDRequest
	var md metadata.MD
	iss := newTestIssuer(t, &fakeBroker{fetch: func(ctx context.Context, req *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
		got = req
		md, _ = metadata.FromIncomingContext(ctx)
		return &brokerpb.FetchJWTSVIDResponse{Svids: []*brokerpb.JWTSVID{{
			SpiffeId: "spiffe://example.org/ns/team-a/sa/web", Svid: token,
		}}}, nil
	}})

	tok, expiry, err := iss.FetchJWTSVID(context.Background(), ref, "cracha-broker")
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if tok != token {
		t.Errorf("token differs from what the issuer returned")
	}
	if !expiry.Equal(exp) {
		t.Errorf("expiry %v, want %v (the token's exp)", expiry, exp)
	}

	// The mandatory security header.
	if v := md.Get(brokerHeaderKey); len(v) != 1 || v[0] != brokerHeaderValue {
		t.Errorf("metadata %s=%v, want [%s]", brokerHeaderKey, v, brokerHeaderValue)
	}
	// The request: audience, and the pod reference with all of namespace,
	// name and UID so the server verifies the UID.
	if aud := got.GetAudience(); len(aud) != 1 || aud[0] != "cracha-broker" {
		t.Errorf("audience %v, want [cracha-broker]", aud)
	}
	var kref brokerpb.KubernetesObjectReference
	if err := got.GetReference().GetReference().UnmarshalTo(&kref); err != nil {
		t.Fatalf("the reference is not a KubernetesObjectReference: %v", err)
	}
	if kref.GetType().GetPlural() != "pods" || kref.GetType().GetGroup() != "core" {
		t.Errorf("type %v, want pods/core", kref.GetType())
	}
	if kref.GetKey().GetNamespace() != ref.Namespace || kref.GetKey().GetName() != ref.Name || kref.GetUid() != ref.UID {
		t.Errorf("reference %v, want %v", &kref, ref)
	}
}

func TestFetchJWTSVIDClassifiesErrors(t *testing.T) {
	cases := []struct {
		code codes.Code
		want issuer.Kind
	}{
		{codes.NotFound, issuer.NotFoundYet},
		{codes.Unavailable, issuer.Unavailable},
		{codes.PermissionDenied, issuer.PermissionDenied},
		{codes.InvalidArgument, issuer.Permanent},
		{codes.Unauthenticated, issuer.Permanent},
		{codes.Internal, issuer.Permanent},
	}
	for _, c := range cases {
		iss := newTestIssuer(t, &fakeBroker{fetch: func(context.Context, *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
			return nil, status.Error(c.code, "refused")
		}})
		_, _, err := iss.FetchJWTSVID(context.Background(), ref, "cracha-broker")
		if err == nil {
			t.Fatalf("%s: expected an error", c.code)
		}
		if got := issuer.Classify(err); got != c.want {
			t.Errorf("%s: classified as %s, want %s (%v)", c.code, got, c.want, err)
		}
	}
}

func TestFetchJWTSVIDEmptyIsNotFoundYet(t *testing.T) {
	iss := newTestIssuer(t, &fakeBroker{fetch: func(context.Context, *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
		return &brokerpb.FetchJWTSVIDResponse{}, nil
	}})
	_, _, err := iss.FetchJWTSVID(context.Background(), ref, "cracha-broker")
	if issuer.Classify(err) != issuer.NotFoundYet {
		t.Fatalf("an empty answer must be retried as not found yet, got %v", err)
	}
}

func TestFetchJWTSVIDWrongAudienceIsPermanent(t *testing.T) {
	token := jwttest.Mint(jwttest.Claims{
		Subject: "spiffe://example.org/ns/team-a/sa/web", Audience: []string{"other"},
		Expiry: time.Now().Add(time.Minute),
	})
	iss := newTestIssuer(t, &fakeBroker{fetch: func(context.Context, *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
		return &brokerpb.FetchJWTSVIDResponse{Svids: []*brokerpb.JWTSVID{{Svid: token}}}, nil
	}})
	_, _, err := iss.FetchJWTSVID(context.Background(), ref, "cracha-broker")
	if issuer.Classify(err) != issuer.Permanent {
		t.Fatalf("a token for another audience must be a permanent failure, got %v", err)
	}
}

func TestFetchJWTSVIDIncompleteReference(t *testing.T) {
	called := false
	iss := newTestIssuer(t, &fakeBroker{fetch: func(context.Context, *brokerpb.FetchJWTSVIDRequest) (*brokerpb.FetchJWTSVIDResponse, error) {
		called = true
		return &brokerpb.FetchJWTSVIDResponse{}, nil
	}})
	_, _, err := iss.FetchJWTSVID(context.Background(), issuer.PodRef{Namespace: "ns", Name: "pod"}, "cracha-broker")
	if issuer.Classify(err) != issuer.Permanent || called {
		t.Fatalf("a reference without a UID must be refused before any call, got %v (called=%v)", err, called)
	}
}
