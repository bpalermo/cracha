package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/bpalermo/cracha/access/internal/api"
)

// accessAPI is what the CLI calls: *api.Client, or a fake in tests.
type accessAPI interface {
	Grant(context.Context, *api.GrantRequest) (*api.WriteResponse, error)
	Revoke(context.Context, *api.RevokeRequest) (*api.WriteResponse, error)
	Approve(context.Context, *api.DecideRequest) (*api.WriteResponse, error)
	Reject(context.Context, *api.DecideRequest) (*api.WriteResponse, error)
	List(context.Context, *api.ListRequest) (*api.ListResponse, error)
	Explain(context.Context, *api.ExplainRequest) (*api.ExplainResponse, error)
	Pending(context.Context, *api.PendingRequest) (*api.PendingResponse, error)
}

// call is one CLI call, its flags parsed.
type call func(context.Context, accessAPI) (any, error)

// command binds a command's flags and returns its call, which checks
// them once parsed.
type command func(fs *flag.FlagSet, e env) func() (call, error)

var commands = map[string]command{
	"grant":   grantCommand,
	"revoke":  revokeCommand,
	"approve": decideCommand(func(ctx context.Context, c accessAPI, r *api.DecideRequest) (any, error) { return c.Approve(ctx, r) }),
	"reject":  decideCommand(func(ctx context.Context, c accessAPI, r *api.DecideRequest) (any, error) { return c.Reject(ctx, r) }),
	"list":    listCommand,
	"explain": explainCommand,
	"pending": pendingCommand,
}

// connFlags is how the CLI reaches the service: its address and SPIFFE
// ID, and the Workload API the caller's SVID comes from.
type connFlags struct {
	server      string
	serverID    string
	workloadAPI string
	timeout     time.Duration
}

func (f *connFlags) bind(fs *flag.FlagSet, e env, lookup func(string) (string, bool)) {
	socket, ok := lookup("SPIFFE_ENDPOINT_SOCKET")
	if !ok {
		socket = "unix:///run/spire/sockets/agent.sock"
	}
	fs.StringVar(&f.server, "server", e.str("access-server", ""), "cracha-access's gRPC address, host:port (CRACHA_ACCESS_SERVER)")
	fs.StringVar(&f.serverID, "server-spiffe-id", e.str("access-spiffe-id", ""), "cracha-access's SPIFFE ID, which its certificate must carry (CRACHA_ACCESS_SPIFFE_ID)")
	fs.StringVar(&f.workloadAPI, "workload-api-socket", socket, "the SPIFFE Workload API the caller's SVID comes from (SPIFFE_ENDPOINT_SOCKET)")
	fs.DurationVar(&f.timeout, "timeout", 30*time.Second, "deadline of the call")
}

// dial connects to the service with the caller's SVID. Tests replace it.
var dial = func(ctx context.Context, f connFlags) (accessAPI, func(), error) {
	if f.server == "" || f.serverID == "" {
		return nil, nil, errors.New("--server and --server-spiffe-id are required")
	}
	id, err := spiffeid.FromString(f.serverID)
	if err != nil {
		return nil, nil, fmt.Errorf("--server-spiffe-id: %w", err)
	}
	src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(f.workloadAPI)))
	if err != nil {
		return nil, nil, fmt.Errorf("workload api %s: %w", f.workloadAPI, err)
	}
	conn, err := api.Dial(f.server, src, src, id)
	if err != nil {
		_ = src.Close()
		return nil, nil, err
	}
	return api.NewClient(conn), func() { _ = conn.Close(); _ = src.Close() }, nil
}

func runCLI(ctx context.Context, name string, cmd command, args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cracha-access "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var conn connFlags
	conn.bind(fs, env(lookup), lookup)
	build := cmd(fs, env(lookup))
	err := fs.Parse(args)
	var c call
	if err == nil {
		c, err = build()
	}
	return exit(stderr, err, func() error {
		client, closeFn, err := dial(ctx, conn)
		if err != nil {
			return err
		}
		defer closeFn()
		ctx, cancel := context.WithTimeout(ctx, conn.timeout)
		defer cancel()
		resp, err := c(ctx, client)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	})
}

// parseResource parses kind:name.
func parseResource(s string) (api.Resource, error) {
	kind, name, ok := strings.Cut(s, ":")
	if !ok || kind == "" || name == "" {
		return api.Resource{}, fmt.Errorf("--resource %q: want kind:name, such as s3_bucket:payments-exports or service:payments-api", s)
	}
	return api.Resource{Kind: kind, Name: name}, nil
}

// splitList splits a comma-separated flag, dropping empties.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// holderFlags are a write's who, what and why.
type holderFlags struct {
	subject, service, resource, relation, reason, requester string
}

func (h *holderFlags) bind(fs *flag.FlagSet, e env) {
	fs.StringVar(&h.subject, "subject", "", "the workload, as its authorization subject encoding (design 4.3)")
	fs.StringVar(&h.service, "service", "", "the service whose members are related, instead of --subject")
	fs.StringVar(&h.resource, "resource", "", "kind:name: s3_bucket:<bucket>, dynamodb_table:<table>, or service:<name> for a membership")
	fs.StringVar(&h.relation, "relation", "", "reader or writer on a resource; member on a service; owner or approver on either")
	fs.StringVar(&h.reason, "reason", "", "why (required; recorded)")
	fs.StringVar(&h.requester, "requester", e.str("requester", ""), "who asks: a person or a job, recorded beside the caller's SPIFFE ID (CRACHA_REQUESTER)")
}

func grantCommand(fs *flag.FlagSet, e env) func() (call, error) {
	var h holderFlags
	h.bind(fs, e)
	expiresAt := fs.String("expires-at", "", "RFC 3339 time the relationship ends at")
	clusters := fs.String("clusters", "", "comma-separated clusters the relationship is bound to")
	breakGlass := fs.Bool("break-glass", false, "apply a write on a sensitive target at once (needs --expires-at within the cap; logged at WARN)")
	return func() (call, error) {
		res, err := parseResource(h.resource)
		if err != nil {
			return nil, err
		}
		req := &api.GrantRequest{
			Subject: h.subject, Service: h.service, Resource: res, Relation: h.relation, ExpiresAt: *expiresAt,
			Clusters: splitList(*clusters), Reason: h.reason, Requester: h.requester, BreakGlass: *breakGlass,
		}
		return func(ctx context.Context, c accessAPI) (any, error) { return c.Grant(ctx, req) }, nil
	}
}

func revokeCommand(fs *flag.FlagSet, e env) func() (call, error) {
	var h holderFlags
	h.bind(fs, e)
	return func() (call, error) {
		res, err := parseResource(h.resource)
		if err != nil {
			return nil, err
		}
		req := &api.RevokeRequest{Subject: h.subject, Service: h.service, Resource: res, Relation: h.relation, Reason: h.reason, Requester: h.requester}
		return func(ctx context.Context, c accessAPI) (any, error) { return c.Revoke(ctx, req) }, nil
	}
}

func decideCommand(do func(context.Context, accessAPI, *api.DecideRequest) (any, error)) command {
	return func(fs *flag.FlagSet, e env) func() (call, error) {
		id := fs.String("id", "", "the pending request's ID")
		reason := fs.String("reason", "", "why (required; recorded)")
		requester := fs.String("requester", e.str("requester", ""), "who decides: a person or a job (CRACHA_REQUESTER)")
		return func() (call, error) {
			if *id == "" && fs.NArg() == 1 {
				*id = fs.Arg(0)
			}
			req := &api.DecideRequest{ID: *id, Reason: *reason, Requester: *requester}
			return func(ctx context.Context, c accessAPI) (any, error) { return do(ctx, c, req) }, nil
		}
	}
}

func listCommand(fs *flag.FlagSet, _ env) func() (call, error) {
	subject := fs.String("subject", "", "a workload: its own relationships and its service's")
	service := fs.String("service", "", "a service: its members and what they are related to")
	resource := fs.String("resource", "", "kind:name: who reaches the resource")
	return func() (call, error) {
		req := &api.ListRequest{Subject: *subject, Service: *service}
		if *resource != "" {
			res, err := parseResource(*resource)
			if err != nil {
				return nil, err
			}
			req.Resource = &res
		}
		return func(ctx context.Context, c accessAPI) (any, error) { return c.List(ctx, req) }, nil
	}
}

func explainCommand(fs *flag.FlagSet, _ env) func() (call, error) {
	subject := fs.String("subject", "", "the workload, as its authorization subject encoding")
	cluster := fs.String("cluster", "", "only this cluster's scope")
	return func() (call, error) {
		req := &api.ExplainRequest{Subject: *subject, Cluster: *cluster}
		return func(ctx context.Context, c accessAPI) (any, error) { return c.Explain(ctx, req) }, nil
	}
}

func pendingCommand(fs *flag.FlagSet, _ env) func() (call, error) {
	resource := fs.String("resource", "", "kind:name: only this target's requests")
	return func() (call, error) {
		req := &api.PendingRequest{}
		if *resource != "" {
			res, err := parseResource(*resource)
			if err != nil {
				return nil, err
			}
			req.Resource = &res
		}
		return func(ctx context.Context, c accessAPI) (any, error) { return c.Pending(ctx, req) }, nil
	}
}
