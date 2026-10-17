package driver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bpalermo/cracha/csi/internal/issuer"
	"github.com/bpalermo/cracha/csi/internal/jwttest"
	"github.com/bpalermo/cracha/csi/internal/token"
	"github.com/bpalermo/cracha/csi/internal/tokenreview"
)

const (
	podUID    = "7e3c1a2b-0000-4000-8000-000000000001"
	podNS     = "team-a"
	podName   = "web-0"
	podSA     = "web"
	subject   = "spiffe://example.org/ns/team-a/sa/web"
	volumeID  = "csi-0123456789abcdef"
	saToken1  = "sa-token-1"
	saToken2  = "sa-token-2"
	saTokenNS = "system:serviceaccount:team-a:web"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// clock is a settable time source.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// harness is a Driver with fakes around it.
type harness struct {
	d        *Driver
	issuer   *issuer.Fake
	reviewer *tokenreview.Fake
	clock    *clock
	target   string
}

// goodReviewer binds every known SA token to the test pod.
func goodReviewer() *tokenreview.Fake {
	return &tokenreview.Fake{Fn: func(tok, aud string) (tokenreview.Result, error) {
		if aud != DefaultSATokenAudience {
			return tokenreview.Result{}, errors.New("wrong audience " + aud)
		}
		switch tok {
		case saToken1, saToken2:
			return tokenreview.Result{Username: saTokenNS, PodUID: podUID}, nil
		}
		return tokenreview.Result{}, errors.New("unknown token")
	}}
}

// mint returns a token for the test pod issued at the clock's now.
func mint(c *clock, ttl time.Duration) issuer.Result {
	exp := c.now.Add(ttl)
	return issuer.Result{
		Token: jwttest.Mint(jwttest.Claims{
			Subject: subject, Audience: []string{DefaultAudience}, IssuedAt: c.now, Expiry: exp,
		}),
		Expiry: exp,
	}
}

func newHarness(t *testing.T, iss *issuer.Fake, rev *tokenreview.Fake) *harness {
	t.Helper()
	c := &clock{now: t0}
	// A fast retry policy, so the retry path is exercised but a permanent
	// failure test does not wait.
	retrying := issuer.WithRetry(iss, issuer.RetryPolicy{
		Deadline: 2 * time.Second, Initial: time.Millisecond, Max: 5 * time.Millisecond,
	}, nil)
	d, err := New(Config{
		NodeID: "node-1",
		Owner:  token.Owner{UID: os.Getuid(), GID: os.Getgid()},
		Now:    c.Now,
	}, retrying, rev, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{
		d: d, issuer: iss, reviewer: rev, clock: c,
		target: filepath.Join(t.TempDir(), "pods", podUID, "volumes", "kubernetes.io~csi", "cracha", "mount"),
	}
}

func saTokensJSON(t *testing.T, tok string, exp time.Time) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		DefaultSATokenAudience: map[string]any{"token": tok, "expirationTimestamp": exp},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (h *harness) publishRequest(t *testing.T, saTok string) *csi.NodePublishVolumeRequest {
	return &csi.NodePublishVolumeRequest{
		VolumeId:   volumeID,
		TargetPath: h.target,
		Readonly:   true,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
		},
		VolumeContext: map[string]string{
			ctxEphemeral:    "true",
			ctxPodUID:       podUID,
			ctxPodName:      podName,
			ctxPodNamespace: podNS,
			ctxSAName:       podSA,
			ctxSATokens:     saTokensJSON(t, saTok, h.clock.now.Add(10*time.Minute)),
		},
	}
}

func (h *harness) publish(t *testing.T, req *csi.NodePublishVolumeRequest) error {
	t.Helper()
	_, err := h.d.NodePublishVolume(context.Background(), req)
	return err
}

func (h *harness) readToken(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.target, token.FileName))
	if err != nil {
		t.Fatalf("reading the token: %v", err)
	}
	return string(raw)
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("got %v, want code %s", err, code)
	}
}

func TestPublishHappyPath(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	want := mint(h.clock, 5*time.Minute)
	*iss = *issuer.NewFake(want)

	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("NodePublishVolume: %v", err)
	}
	if got := h.readToken(t); got != want.Token {
		t.Errorf("the token on disk is not the issuer's")
	}
	fi, err := os.Stat(filepath.Join(h.target, token.FileName))
	if err != nil || fi.Mode().Perm() != token.Mode {
		t.Errorf("token file mode %v (err %v), want %o", fi, err, token.Mode)
	}

	calls := iss.Calls()
	if len(calls) != 1 {
		t.Fatalf("issuer called %d times, want 1", len(calls))
	}
	if calls[0].Audience != DefaultAudience {
		t.Errorf("audience %q, want %q", calls[0].Audience, DefaultAudience)
	}
	if ref := calls[0].Ref; ref.Namespace != podNS || ref.Name != podName || ref.UID != podUID {
		t.Errorf("pod reference %v, want %s/%s %s", ref, podNS, podName, podUID)
	}
	if h.reviewer.Calls() != 1 {
		t.Errorf("reviewer called %d times, want 1", h.reviewer.Calls())
	}

	entry, ok := h.d.Registry().Get(volumeID)
	if !ok {
		t.Fatal("the volume is not registered")
	}
	if entry.PodUID != podUID || entry.Namespace != podNS || entry.Name != podName ||
		entry.ServiceAccount != podSA || entry.TargetPath != h.target {
		t.Errorf("registry entry %+v", entry)
	}
	if !entry.TokenIssued.Equal(t0) || !entry.TokenExpiry.Equal(want.Expiry) {
		t.Errorf("token times %v/%v, want %v/%v", entry.TokenIssued, entry.TokenExpiry, t0, want.Expiry)
	}
}

func TestPublishRejectsNonEphemeral(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	for _, tc := range []struct {
		name   string
		mutate func(*csi.NodePublishVolumeRequest)
	}{
		{"no ephemeral flag", func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, ctxEphemeral) }},
		{"ephemeral false", func(r *csi.NodePublishVolumeRequest) { r.VolumeContext[ctxEphemeral] = "false" }},
		{"no pod uid", func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, ctxPodUID) }},
		{"bad pod uid", func(r *csi.NodePublishVolumeRequest) { r.VolumeContext[ctxPodUID] = "../etc" }},
		{"no namespace", func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, ctxPodNamespace) }},
		{"no sa tokens", func(r *csi.NodePublishVolumeRequest) { delete(r.VolumeContext, ctxSATokens) }},
		{"other audience token only", func(r *csi.NodePublishVolumeRequest) {
			r.VolumeContext[ctxSATokens] = `{"other":{"token":"x","expirationTimestamp":"2026-10-17T12:10:00Z"}}`
		}},
		{"block volume", func(r *csi.NodePublishVolumeRequest) {
			r.VolumeCapability.AccessType = &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}}
		}},
		{"no volume id", func(r *csi.NodePublishVolumeRequest) { r.VolumeId = "" }},
		{"relative target", func(r *csi.NodePublishVolumeRequest) { r.TargetPath = "mount" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := h.publishRequest(t, saToken1)
			tc.mutate(req)
			wantCode(t, h.publish(t, req), codes.InvalidArgument)
		})
	}
	if n := len(iss.Calls()); n != 0 {
		t.Errorf("issuer called %d times for rejected requests", n)
	}
	if n := h.reviewer.Calls(); n != 0 {
		t.Errorf("reviewer called %d times for rejected requests", n)
	}
	if h.d.Registry().Len() != 0 {
		t.Error("a rejected volume was registered")
	}
}

func TestPublishRejectsSATokenMismatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  tokenreview.Result
		err  error
	}{
		{"not authenticated", tokenreview.Result{}, errors.New("TokenReview: not authenticated")},
		{"other pod uid", tokenreview.Result{Username: saTokenNS, PodUID: "7e3c1a2b-0000-4000-8000-000000000002"}, nil},
		{"unbound token", tokenreview.Result{Username: saTokenNS}, nil},
		{"other service account", tokenreview.Result{Username: "system:serviceaccount:team-a:db", PodUID: podUID}, nil},
		{"other namespace", tokenreview.Result{Username: "system:serviceaccount:team-b:web", PodUID: podUID}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iss := issuer.NewFake()
			rev := &tokenreview.Fake{Fn: func(string, string) (tokenreview.Result, error) { return tc.res, tc.err }}
			h := newHarness(t, iss, rev)
			*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

			wantCode(t, h.publish(t, h.publishRequest(t, saToken1)), codes.PermissionDenied)
			if n := len(iss.Calls()); n != 0 {
				t.Errorf("issuer called %d times after a failed context check", n)
			}
			if _, err := os.Stat(filepath.Join(h.target, token.FileName)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a token was written: %v", err)
			}
		})
	}
}

func TestPublishRetriesNotFound(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	want := mint(h.clock, 5*time.Minute)
	*iss = *issuer.NewFake(
		issuer.Result{Err: issuer.NewError(issuer.NotFoundYet, errors.New("entry not synced"))},
		issuer.Result{Err: issuer.NewError(issuer.Unavailable, errors.New("agent restarting"))},
		want,
	)
	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("NodePublishVolume: %v", err)
	}
	if n := len(iss.Calls()); n != 3 {
		t.Errorf("issuer called %d times, want 3", n)
	}
	if h.readToken(t) != want.Token {
		t.Error("the token on disk is not the one eventually issued")
	}
}

func TestPublishPermissionDenied(t *testing.T) {
	iss := issuer.NewFake(issuer.Result{Err: issuer.NewError(issuer.PermissionDenied, errors.New("RBAC"))})
	h := newHarness(t, iss, goodReviewer())

	wantCode(t, h.publish(t, h.publishRequest(t, saToken1)), codes.PermissionDenied)
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times, want 1: permission denied is not retried", n)
	}
	if h.d.Registry().Len() != 0 {
		t.Error("a failed volume stayed registered")
	}
}

func TestPublishRefusesLongTTL(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, time.Hour))

	err := h.publish(t, h.publishRequest(t, saToken1))
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "jwtSVIDTTL") {
		t.Errorf("the rejection must name the fix, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.target, token.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a token that outlives the invariant was written: %v", err)
	}
	if h.d.Registry().Len() != 0 {
		t.Error("a refused volume was registered")
	}
}

func TestPublishRefusesForeignSubject(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	exp := h.clock.now.Add(5 * time.Minute)
	*iss = *issuer.NewFake(issuer.Result{
		Token: jwttest.Mint(jwttest.Claims{
			Subject: "spiffe://example.org/ns/team-b/sa/web", Audience: []string{DefaultAudience},
			IssuedAt: h.clock.now, Expiry: exp,
		}),
		Expiry: exp,
	})
	wantCode(t, h.publish(t, h.publishRequest(t, saToken1)), codes.FailedPrecondition)
	if _, err := os.Stat(filepath.Join(h.target, token.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("another pod's token was written: %v", err)
	}
}

func TestRepublishRotatesAtHalfLife(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	first := mint(h.clock, 5*time.Minute)
	*iss = *issuer.NewFake(first)

	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Before the half-life: nothing happens.
	h.clock.now = t0.Add(2 * time.Minute)
	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times before the half-life, want 1", n)
	}
	if h.readToken(t) != first.Token {
		t.Error("the token was replaced before its half-life")
	}
	if n := h.reviewer.Calls(); n != 1 {
		t.Errorf("reviewer called %d times for the same SA token, want 1", n)
	}

	// Exactly at the half-life: still fresh.
	h.clock.now = t0.Add(150 * time.Second)
	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("republish at half-life: %v", err)
	}
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times at the half-life, want 1", n)
	}

	// Past the half-life: replaced.
	h.clock.now = t0.Add(151 * time.Second)
	second := mint(h.clock, 5*time.Minute)
	*iss = *issuer.NewFake(second)
	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("republish past the half-life: %v", err)
	}
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times past the half-life, want 1 on the new fake", n)
	}
	if h.readToken(t) != second.Token {
		t.Error("the token was not replaced past its half-life")
	}
	entry, _ := h.d.Registry().Get(volumeID)
	if !entry.TokenExpiry.Equal(second.Expiry) {
		t.Errorf("registry expiry %v, want %v", entry.TokenExpiry, second.Expiry)
	}
}

func TestRepublishReviewsRotatedSAToken(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Kubelet rotated the SA token: it is reviewed again, the JWT-SVID is
	// still fresh so it is not.
	if err := h.publish(t, h.publishRequest(t, saToken2)); err != nil {
		t.Fatalf("republish with a new SA token: %v", err)
	}
	if n := h.reviewer.Calls(); n != 2 {
		t.Errorf("reviewer called %d times, want 2", n)
	}
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times, want 1", n)
	}

	// The context check fails on republish: the publish fails even though
	// the token on disk is fresh.
	h.reviewer.Fn = func(string, string) (tokenreview.Result, error) {
		return tokenreview.Result{Username: saTokenNS, PodUID: "7e3c1a2b-0000-4000-8000-00000000dead"}, nil
	}
	wantCode(t, h.publish(t, h.publishRequest(t, "sa-token-3")), codes.PermissionDenied)
}

func TestRepublishRewritesMissingToken(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := os.Remove(filepath.Join(h.target, token.FileName)); err != nil {
		t.Fatal(err)
	}
	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if n := len(iss.Calls()); n != 2 {
		t.Errorf("issuer called %d times, want 2: a missing token is fetched again", n)
	}
	h.readToken(t)
}

func TestUnpublishIdempotent(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	req := &csi.NodeUnpublishVolumeRequest{VolumeId: volumeID, TargetPath: h.target}
	for i := range 2 {
		if _, err := h.d.NodeUnpublishVolume(context.Background(), req); err != nil {
			t.Fatalf("unpublish #%d: %v", i+1, err)
		}
	}
	if _, err := os.Stat(h.target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the target directory remains: %v", err)
	}
	if h.d.Registry().Len() != 0 {
		t.Error("the volume stayed registered")
	}

	// A volume never published.
	unknown := &csi.NodeUnpublishVolumeRequest{VolumeId: "csi-unknown", TargetPath: filepath.Join(t.TempDir(), "never")}
	if _, err := h.d.NodeUnpublishVolume(context.Background(), unknown); err != nil {
		t.Errorf("unpublish of an unknown volume: %v", err)
	}
	if _, err := h.d.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{VolumeId: volumeID}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unpublish without a target path: %v", err)
	}

	// After an unpublish, a publish of the same volume ID starts over.
	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("publish after unpublish: %v", err)
	}
	if n := len(iss.Calls()); n != 2 {
		t.Errorf("issuer called %d times, want 2", n)
	}
}

func TestIdentityAndNodeInfo(t *testing.T) {
	h := newHarness(t, issuer.NewFake(), goodReviewer())
	ctx := context.Background()

	info, err := h.d.GetPluginInfo(ctx, &csi.GetPluginInfoRequest{})
	if err != nil || info.GetName() != DriverName {
		t.Errorf("GetPluginInfo: %v, %v", info, err)
	}
	caps, err := h.d.GetPluginCapabilities(ctx, &csi.GetPluginCapabilitiesRequest{})
	if err != nil || len(caps.GetCapabilities()) != 0 {
		t.Errorf("GetPluginCapabilities: %v, %v", caps, err)
	}
	probe, err := h.d.Probe(ctx, &csi.ProbeRequest{})
	if err != nil || !probe.GetReady().GetValue() {
		t.Errorf("Probe: %v, %v", probe, err)
	}
	node, err := h.d.NodeGetInfo(ctx, &csi.NodeGetInfoRequest{})
	if err != nil || node.GetNodeId() != "node-1" {
		t.Errorf("NodeGetInfo: %v, %v", node, err)
	}
	// VOLUME_MOUNT_GROUP and nothing else: kubelet hands the pod's fsGroup
	// to NodePublishVolume only when the plugin advertises it.
	ncaps, err := h.d.NodeGetCapabilities(ctx, &csi.NodeGetCapabilitiesRequest{})
	if err != nil || len(ncaps.GetCapabilities()) != 1 ||
		ncaps.GetCapabilities()[0].GetRpc().GetType() != csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP {
		t.Errorf("NodeGetCapabilities: %v, %v; want VOLUME_MOUNT_GROUP alone", ncaps, err)
	}
	if _, err := h.d.NodeStageVolume(ctx, &csi.NodeStageVolumeRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("NodeStageVolume: %v", err)
	}
}

func TestNewRequiresNodeID(t *testing.T) {
	if _, err := New(Config{}, issuer.NewFake(), goodReviewer(), nil); err == nil {
		t.Error("New without a node ID succeeded")
	}
}

// withMountGroup sets the volume mount group of a publish request: what
// kubelet passes for a pod with an fsGroup.
func withMountGroup(req *csi.NodePublishVolumeRequest, group string) *csi.NodePublishVolumeRequest {
	req.VolumeCapability.GetMount().VolumeMountGroup = group
	return req
}

// usableGroup returns a group other than the process's primary one that it
// may give a file without CAP_CHOWN, and skips the test when there is none:
// a sandbox with a user namespace maps the supplementary groups to the
// overflow group, which cannot own a file.
func usableGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var refused []string
	for _, g := range groups {
		if g == os.Getgid() {
			continue
		}
		if err := os.Chown(probe, -1, g); err != nil {
			refused = append(refused, err.Error())
			continue
		}
		return g
	}
	t.Skipf("skipping: no group of this process but its primary one (%d) may own a file here: %v", os.Getgid(), refused)
	return -1
}

// checkOwner asserts the owner and mode of the token and of its directory.
func (h *harness) checkOwner(t *testing.T, uid, gid int) {
	t.Helper()
	for _, c := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(h.target, token.FileName), token.Mode},
		{h.target, token.DirMode},
	} {
		fi, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != c.mode {
			t.Errorf("%s: mode %o, want %o", c.path, fi.Mode().Perm(), c.mode)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("%s: no stat", c.path)
		}
		if int(st.Uid) != uid || int(st.Gid) != gid {
			t.Errorf("%s: owner %d:%d, want %d:%d", c.path, st.Uid, st.Gid, uid, gid)
		}
	}
}

// A pod with an fsGroup: kubelet passes it as the volume mount group and the
// token is written with that group, 0640, in a directory of that group.
func TestPublishMountGroup(t *testing.T) {
	gid := usableGroup(t)
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	if err := h.publish(t, withMountGroup(h.publishRequest(t, saToken1), strconv.Itoa(gid))); err != nil {
		t.Fatalf("NodePublishVolume with a mount group: %v", err)
	}
	h.checkOwner(t, os.Getuid(), gid)
	entry, _ := h.d.Registry().Get(volumeID)
	if entry.TokenOwner != (token.Owner{UID: os.Getuid(), GID: gid}) {
		t.Errorf("registry owner %+v, want uid %d gid %d", entry.TokenOwner, os.Getuid(), gid)
	}
}

// A pod without an fsGroup: the token gets the configured owner, the
// plugin's --token-uid and --token-gid.
func TestPublishWithoutMountGroup(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	req := h.publishRequest(t, saToken1)
	if got := req.VolumeCapability.GetMount().GetVolumeMountGroup(); got != "" {
		t.Fatalf("the request carries a mount group %q", got)
	}
	if err := h.publish(t, req); err != nil {
		t.Fatalf("NodePublishVolume: %v", err)
	}
	h.checkOwner(t, os.Getuid(), os.Getgid())
}

// A mount group that is not a group ID is refused before anything is
// fetched or written.
func TestPublishRejectsInvalidMountGroup(t *testing.T) {
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	*iss = *issuer.NewFake(mint(h.clock, 5*time.Minute))

	for _, group := range []string{"nobody", "-1", "1.5", "4294967295", "1e3", " 1"} {
		t.Run(group, func(t *testing.T) {
			err := h.publish(t, withMountGroup(h.publishRequest(t, saToken1), group))
			wantCode(t, err, codes.InvalidArgument)
			if !strings.Contains(err.Error(), "volume_mount_group") {
				t.Errorf("the rejection does not name the field: %v", err)
			}
		})
	}
	if n := len(iss.Calls()); n != 0 {
		t.Errorf("issuer called %d times for rejected requests", n)
	}
	if n := h.reviewer.Calls(); n != 0 {
		t.Errorf("reviewer called %d times for rejected requests", n)
	}
	if _, err := os.Stat(h.target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the target directory was created: %v", err)
	}
}

// A republish that asks for another group (which cannot happen for one pod,
// since the fsGroup is in the pod spec) rewrites the token for it even though
// the one on disk is fresh.
func TestRepublishRewritesForNewMountGroup(t *testing.T) {
	gid := usableGroup(t)
	iss := issuer.NewFake()
	h := newHarness(t, iss, goodReviewer())
	first := mint(h.clock, 5*time.Minute)
	*iss = *issuer.NewFake(first)

	if err := h.publish(t, h.publishRequest(t, saToken1)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	h.checkOwner(t, os.Getuid(), os.Getgid())

	h.clock.now = t0.Add(time.Minute)
	second := mint(h.clock, 5*time.Minute)
	*iss = *issuer.NewFake(second)
	if err := h.publish(t, withMountGroup(h.publishRequest(t, saToken1), strconv.Itoa(gid))); err != nil {
		t.Fatalf("republish with a mount group: %v", err)
	}
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times on the new fake, want 1: a new group means a rewrite", n)
	}
	if h.readToken(t) != second.Token {
		t.Error("the token was not rewritten for the new group")
	}
	h.checkOwner(t, os.Getuid(), gid)

	// The same group again: the fresh token stays.
	h.clock.now = t0.Add(2 * time.Minute)
	if err := h.publish(t, withMountGroup(h.publishRequest(t, saToken1), strconv.Itoa(gid))); err != nil {
		t.Fatalf("republish with the same mount group: %v", err)
	}
	if n := len(iss.Calls()); n != 1 {
		t.Errorf("issuer called %d times, want 1: the same group keeps the fresh token", n)
	}
	if h.readToken(t) != second.Token {
		t.Error("the token was replaced although fresh and owned by the right group")
	}
}
