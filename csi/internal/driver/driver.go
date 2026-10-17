// Package driver is the csi.cracha.dev node plugin (docs/design.md, section
// 7): the CSI Identity and Node services that put a pod's JWT-SVID where the
// AWS SDK reads it before the pod's containers start, and keep it fresh.
//
// Identity and Node services only, inline ephemeral volumes only. There is no
// Controller service and no staging. Every NodePublishVolume:
//
//  1. reads the pod from the volume context kubelet fills in
//     (podInfoOnMount), and refuses anything that is not an inline ephemeral
//     volume;
//  2. verifies the kubelet-supplied bound service account token with a
//     TokenReview and requires it to be bound to that very pod UID;
//  3. fetches the pod's JWT-SVID through the issuer adapter, checks its
//     claims (audience, subject, TTL) and writes it atomically to
//     <target_path>/token, mode 0640, owned by the pod's fsGroup.
//
// The group is the CSI spec's volume mount group: the plugin advertises
// VOLUME_MOUNT_GROUP, kubelet passes the pod's fsGroup in the mount
// capability, and the token is given that group so that a pod running as any
// user reads it. A pod without an fsGroup gets the plugin's --token-gid.
//
// Nothing is mounted. The token is written straight into the target path
// kubelet created, as a plain file on the kubelet's volume directory, and the
// container runtime bind-mounts that directory into the pod (read-only when
// the volume says so, which the webhook does). The SPIFFE CSI driver takes
// the same approach for its socket directory. The trade-off: a tmpfs mount
// would keep the token off the node's disk, but mounting needs CAP_SYS_ADMIN,
// and section 7.7 keeps the plugin to CAP_CHOWN; what would be on disk is a
// token that lives at most five minutes, bound to one audience, in a directory
// only root and the pod's group read on the host.
package driver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bpalermo/cracha/csi/internal/issuer"
	"github.com/bpalermo/cracha/csi/internal/token"
	"github.com/bpalermo/cracha/csi/internal/tokenreview"
)

const (
	// DriverName is the CSIDriver object's name, the `driver:` of a pod's
	// inline volume and what the plugin registers with kubelet as.
	DriverName = "csi.cracha.dev"

	// DefaultAudience is the audience of the JWT-SVID on disk: the broker's.
	DefaultAudience = "cracha-broker"
	// DefaultSATokenAudience is the audience of the bound service account
	// token kubelet hands the plugin (the CSIDriver's tokenRequests).
	DefaultSATokenAudience = "cracha-csi"

	// The volume_context keys kubelet fills in for a CSIDriver with
	// podInfoOnMount and tokenRequests.
	ctxPrefix       = "csi.storage.k8s.io/"
	ctxEphemeral    = ctxPrefix + "ephemeral"
	ctxPodUID       = ctxPrefix + "pod.uid"
	ctxPodName      = ctxPrefix + "pod.name"
	ctxPodNamespace = ctxPrefix + "pod.namespace"
	ctxSAName       = ctxPrefix + "serviceAccount.name"
	ctxSATokens     = ctxPrefix + "serviceAccount.tokens"
)

// podUIDPattern accepts a Kubernetes pod UID: a lower-case RFC 4122 UUID for an
// API pod, or the 32-hex-digit config hash a static pod carries.
var podUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$`)

// Config is the plugin's static configuration.
type Config struct {
	// NodeID is reported by NodeGetInfo: the node's name.
	NodeID string
	// Version is reported by GetPluginInfo.
	Version string
	// Audience is the JWT-SVID's audience; empty means DefaultAudience.
	Audience string
	// SATokenAudience is the bound service account token's audience; empty
	// means DefaultSATokenAudience.
	SATokenAudience string
	// MaxTokenTTL is the longest token lifetime written to disk; zero means
	// token.DefaultMaxTTL.
	MaxTokenTTL time.Duration
	// Owner owns the token file.
	Owner token.Owner
	// Now is the clock; nil means time.Now. Tests set it.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Audience == "" {
		c.Audience = DefaultAudience
	}
	if c.SATokenAudience == "" {
		c.SATokenAudience = DefaultSATokenAudience
	}
	if c.MaxTokenTTL <= 0 {
		c.MaxTokenTTL = token.DefaultMaxTTL
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Driver implements the CSI Identity and Node services.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer

	cfg      Config
	issuer   issuer.Issuer
	reviewer tokenreview.Reviewer
	log      *slog.Logger
	registry *Registry
	locks    *keyedMutex
}

// New validates cfg and returns a Driver fetching tokens from iss and checking
// service account tokens with rev. iss is expected to carry its own retry
// policy (issuer.WithRetry).
func New(cfg Config, iss issuer.Issuer, rev tokenreview.Reviewer, log *slog.Logger) (*Driver, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("the node ID is required (set NODE_NAME or --node-id)")
	}
	if iss == nil {
		return nil, errors.New("an issuer is required")
	}
	if rev == nil {
		return nil, errors.New("a token reviewer is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Driver{
		cfg:      cfg.withDefaults(),
		issuer:   iss,
		reviewer: rev,
		log:      log,
		registry: NewRegistry(),
		locks:    newKeyedMutex(),
	}, nil
}

// Registry exposes the published volumes.
func (d *Driver) Registry() *Registry { return d.registry }

// --- Identity ----------------------------------------------------------------

// GetPluginInfo reports the driver name and version.
func (d *Driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: DriverName, VendorVersion: d.cfg.Version}, nil
}

// GetPluginCapabilities reports none: in particular no CONTROLLER_SERVICE.
func (d *Driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

// Probe reports ready. The issuer and the API server can be away, and a
// publish then fails and is retried by kubelet; that is not the plugin being
// unready.
func (d *Driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}

// --- Node --------------------------------------------------------------------

// NodeGetInfo reports the node ID. No topology, no volume limit.
func (d *Driver) NodeGetInfo(context.Context, *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: d.cfg.NodeID}, nil
}

// NodeGetCapabilities advertises VOLUME_MOUNT_GROUP: kubelet then passes the
// pod's fsGroup to NodePublishVolume as the volume mount group, and the
// plugin gives the token that group rather than kubelet walking the volume
// after the fact. No staging, no stats, no expansion.
func (d *Driver) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{
		Capabilities: []*csi.NodeServiceCapability{{
			Type: &csi.NodeServiceCapability_Rpc{
				Rpc: &csi.NodeServiceCapability_RPC{Type: csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP},
			},
		}},
	}, nil
}

// publishRequest is a validated NodePublishVolume.
type publishRequest struct {
	volumeID string
	target   string
	pod      issuer.PodRef
	sa       string
	// mountGroup is the pod's fsGroup, from the volume capability's mount
	// group; -1 when the pod sets none.
	mountGroup int
	// saToken is the bound service account token kubelet issued for the
	// plugin's audience, and saTokenExpiry when kubelet says it expires.
	saToken       string
	saTokenExpiry time.Time
}

// saTokens is the value of the serviceAccount.tokens volume context key: a
// JSON object keyed by audience.
type saTokens map[string]struct {
	Token               string    `json:"token"`
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
}

// NodePublishVolume writes the pod's JWT-SVID into target_path. On a
// republish of a volume it knows, it re-runs the context check and replaces
// the token only when less than half its lifetime remains, when it is gone,
// or when its owner is no longer the one the request asks for.
func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	pr, err := d.validatePublish(req)
	if err != nil {
		d.log.Warn("rejecting NodePublishVolume", "volume_id", req.GetVolumeId(),
			"target_path", req.GetTargetPath(), "error", err)
		return nil, err
	}
	log := d.log.With("volume_id", pr.volumeID, "pod", pr.pod.String(), "target_path", pr.target)

	unlock := d.locks.Lock(pr.volumeID)
	defer unlock()

	now := d.cfg.Now()
	entry, known := d.registry.Get(pr.volumeID)
	if known && (entry.PodUID != pr.pod.UID || entry.TargetPath != pr.target) {
		// The volume ID is derived from the pod UID and the volume name, so
		// this is a stale entry, not a conflict: start over.
		known = false
	}
	if !known {
		entry = Entry{
			VolumeID:       pr.volumeID,
			PodUID:         pr.pod.UID,
			Namespace:      pr.pod.Namespace,
			Name:           pr.pod.Name,
			ServiceAccount: pr.sa,
			TargetPath:     pr.target,
		}
	}

	// Context check (design 7.3, step 2). Any failure fails the publish.
	if err := d.checkContext(ctx, &entry, pr, now); err != nil {
		log.Warn("the pod's service account token does not check out", "error", err)
		return nil, status.Errorf(codes.PermissionDenied, "service account token check failed: %v", err)
	}

	owner := d.owner(pr)
	if known && entry.serves(now, owner) {
		d.registry.Put(entry)
		log.Debug("republish: the token is fresh", "expires", entry.TokenExpiry)
		return &csi.NodePublishVolumeResponse{}, nil
	}

	claims, err := d.fetchAndWrite(ctx, log, pr, owner, now)
	if err != nil {
		return nil, err
	}
	entry.TokenIssued = claims.IssuedAt
	if entry.TokenIssued.IsZero() {
		entry.TokenIssued = now
	}
	entry.TokenExpiry = claims.Expiry
	entry.TokenOwner = owner
	d.registry.Put(entry)

	log.Info("token written", "spiffe_id", claims.ID.String(), "expires", claims.Expiry,
		"uid", owner.UID, "gid", owner.GID, "republish", known)
	return &csi.NodePublishVolumeResponse{}, nil
}

// owner is the owner the token gets: the configured one, with the pod's
// fsGroup as the group when kubelet passed one.
func (d *Driver) owner(pr *publishRequest) token.Owner {
	o := d.cfg.Owner
	if pr.mountGroup >= 0 {
		o.GID = pr.mountGroup
	}
	return o
}

// fetchAndWrite fetches the pod's JWT-SVID, checks it and writes it for
// owner (design 7.3, steps 3 and 4). The error is the status the publish
// returns.
func (d *Driver) fetchAndWrite(ctx context.Context, log *slog.Logger, pr *publishRequest, owner token.Owner, now time.Time) (*token.Claims, error) {
	tok, _, err := d.issuer.FetchJWTSVID(ctx, pr.pod, d.cfg.Audience)
	if err != nil {
		log.Error("cannot fetch the pod's JWT-SVID", "kind", issuer.Classify(err).String(), "error", err)
		return nil, fetchStatus(err)
	}
	claims, err := token.Validate(tok, token.Expectation{
		Audience:       d.cfg.Audience,
		Namespace:      pr.pod.Namespace,
		ServiceAccount: pr.sa,
		MaxTTL:         d.cfg.MaxTokenTTL,
		Now:            now,
	})
	if err != nil {
		var ttlErr *token.TTLError
		if errors.As(err, &ttlErr) {
			log.Error("refusing to write a JWT-SVID that outlives --max-token-ttl", "lifetime", ttlErr.Lifetime,
				"max_token_ttl", ttlErr.MaxTTL, "error", err)
		} else {
			log.Error("the issuer returned a JWT-SVID that is not the pod's", "error", err)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "the issuer's JWT-SVID was refused: %v", err)
	}
	if err := token.Write(pr.target, tok, owner); err != nil {
		log.Error("cannot write the token", "error", err)
		return nil, status.Errorf(codes.Internal, "writing the token: %v", err)
	}
	return claims, nil
}

// checkContext verifies the bound service account token of pr against the
// pod it names, asking the API server only for a token it has not already
// accepted. It records the verdict in entry.
func (d *Driver) checkContext(ctx context.Context, entry *Entry, pr *publishRequest, now time.Time) error {
	sum := sha256.Sum256([]byte(pr.saToken))
	if entry.reviewed == sum && now.Before(entry.reviewExpiry) {
		return nil
	}
	err := tokenreview.Check(ctx, d.reviewer, pr.saToken, d.cfg.SATokenAudience, tokenreview.Binding{
		Namespace:      pr.pod.Namespace,
		ServiceAccount: pr.sa,
		PodUID:         pr.pod.UID,
	})
	if err != nil {
		entry.reviewed = [sha256.Size]byte{}
		entry.reviewExpiry = time.Time{}
		return err
	}
	entry.reviewed = sum
	entry.reviewExpiry = pr.saTokenExpiry
	return nil
}

// fetchStatus maps an issuer failure to the gRPC status the publish returns.
// Kubelet retries any failure; the code is for the event on the pod.
func fetchStatus(err error) error {
	switch issuer.Classify(err) {
	case issuer.NotFoundYet:
		return status.Errorf(codes.NotFound, "the issuer has no identity for this pod yet: %v", err)
	case issuer.Unavailable:
		return status.Errorf(codes.Unavailable, "the issuer is unavailable: %v", err)
	case issuer.PermissionDenied:
		return status.Errorf(codes.PermissionDenied, "the issuer refuses to issue for this pod: %v", err)
	default:
		return status.Errorf(codes.Internal, "fetching the pod's JWT-SVID: %v", err)
	}
}

func tokenExists(target string) bool {
	fi, err := os.Stat(filepath.Join(target, token.FileName))
	return err == nil && fi.Mode().IsRegular()
}

func (d *Driver) validatePublish(req *csi.NodePublishVolumeRequest) (*publishRequest, error) {
	target, err := validateTarget(req.GetVolumeId(), req.GetTargetPath())
	if err != nil {
		return nil, err
	}
	if req.GetVolumeCapability().GetBlock() != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s only serves filesystem (mount) volumes", DriverName)
	}
	group, err := mountGroup(req.GetVolumeCapability().GetMount())
	if err != nil {
		return nil, err
	}
	vc := req.GetVolumeContext()
	if vc[ctxEphemeral] != "true" {
		return nil, status.Errorf(codes.InvalidArgument,
			"%s only serves inline ephemeral volumes (volume_context %s=%q); declare it as `volumes: [{csi: {driver: %s}}]` in the pod spec",
			DriverName, ctxEphemeral, vc[ctxEphemeral], DriverName)
	}
	podUID := vc[ctxPodUID]
	if !podUIDPattern.MatchString(podUID) {
		return nil, status.Errorf(codes.InvalidArgument,
			"volume_context %s=%q is not a pod UID (is podInfoOnMount enabled on the CSIDriver?)", ctxPodUID, podUID)
	}
	for _, key := range []string{ctxPodName, ctxPodNamespace, ctxSAName} {
		if vc[key] == "" {
			return nil, status.Errorf(codes.InvalidArgument,
				"volume_context %s is missing (is podInfoOnMount enabled on the CSIDriver?)", key)
		}
	}
	saToken, saTokenExpiry, err := d.saToken(vc)
	if err != nil {
		return nil, err
	}
	return &publishRequest{
		volumeID:      req.GetVolumeId(),
		target:        target,
		pod:           issuer.PodRef{Namespace: vc[ctxPodNamespace], Name: vc[ctxPodName], UID: podUID},
		sa:            vc[ctxSAName],
		mountGroup:    group,
		saToken:       saToken,
		saTokenExpiry: saTokenExpiry,
	}, nil
}

// validateTarget checks the volume ID and the target path every Node call
// carries and returns the cleaned path.
func validateTarget(volumeID, targetPath string) (string, error) {
	if volumeID == "" {
		return "", status.Error(codes.InvalidArgument, "volume_id is required")
	}
	if targetPath == "" {
		return "", status.Error(codes.InvalidArgument, "target_path is required")
	}
	target := filepath.Clean(targetPath)
	if !filepath.IsAbs(target) {
		return "", status.Errorf(codes.InvalidArgument, "target_path %q is not absolute", targetPath)
	}
	return target, nil
}

// mountGroup reads the volume mount group of a mount capability: the pod's
// fsGroup, which kubelet passes because the plugin advertises
// VOLUME_MOUNT_GROUP. -1 when the pod sets none. The spec allows any string,
// so a value that is not a group ID is refused.
func mountGroup(m *csi.VolumeCapability_MountVolume) (int, error) {
	raw := m.GetVolumeMountGroup()
	if raw == "" {
		return -1, nil
	}
	gid, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || gid == math.MaxUint32 {
		return -1, status.Errorf(codes.InvalidArgument,
			"volume_capability.mount.volume_mount_group %q is not a numeric group ID", raw)
	}
	return int(gid), nil
}

// saToken takes the bound service account token for the plugin's audience
// out of the volume context.
func (d *Driver) saToken(vc map[string]string) (string, time.Time, error) {
	raw := vc[ctxSATokens]
	if raw == "" {
		return "", time.Time{}, status.Errorf(codes.InvalidArgument,
			"volume_context %s is missing (does the CSIDriver request a token for audience %q?)", ctxSATokens, d.cfg.SATokenAudience)
	}
	var tokens saTokens
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return "", time.Time{}, status.Errorf(codes.InvalidArgument, "volume_context %s is not valid JSON: %v", ctxSATokens, err)
	}
	sa, ok := tokens[d.cfg.SATokenAudience]
	if !ok || sa.Token == "" {
		return "", time.Time{}, status.Errorf(codes.InvalidArgument,
			"volume_context %s has no token for audience %q (the CSIDriver's tokenRequests must request it)", ctxSATokens, d.cfg.SATokenAudience)
	}
	return sa.Token, sa.ExpirationTimestamp, nil
}

// NodeUnpublishVolume removes the token and the target directory and drops
// the registry entry. Every step tolerates "already done", so an unpublish of
// something never published, or a retry after a partial failure, is OK.
func (d *Driver) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	target, err := validateTarget(req.GetVolumeId(), req.GetTargetPath())
	if err != nil {
		return nil, err
	}
	log := d.log.With("volume_id", req.GetVolumeId(), "target_path", target)

	unlock := d.locks.Lock(req.GetVolumeId())
	defer unlock()

	if err := token.Remove(target); err != nil {
		log.Error("cannot remove the volume", "error", err)
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	if entry, ok := d.registry.Get(req.GetVolumeId()); ok {
		d.registry.Delete(req.GetVolumeId())
		log.Info("unpublished", "pod", fmt.Sprintf("%s/%s (uid %s)", entry.Namespace, entry.Name, entry.PodUID))
	} else {
		log.Debug("unpublish of an unknown volume")
	}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}
