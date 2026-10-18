package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ServiceName is the gRPC service's full name.
const ServiceName = "cracha.access.v1.Access"

// Codec carries messages as JSON: the content subtype "json"
// (application/grpc+json).
type Codec struct{}

// Name implements encoding.Codec.
func (Codec) Name() string { return "json" }

// Marshal implements encoding.Codec.
func (Codec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }

// Unmarshal implements encoding.Codec, refusing unknown fields: a field
// one side does not know is an error, never an ignored request.
func (Codec) Unmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func init() { encoding.RegisterCodec(Codec{}) }

// Server is the service.
type Server interface {
	Grant(context.Context, *GrantRequest) (*WriteResponse, error)
	Revoke(context.Context, *RevokeRequest) (*WriteResponse, error)
	Approve(context.Context, *DecideRequest) (*WriteResponse, error)
	Reject(context.Context, *DecideRequest) (*WriteResponse, error)
	List(context.Context, *ListRequest) (*ListResponse, error)
	Explain(context.Context, *ExplainRequest) (*ExplainResponse, error)
	Pending(context.Context, *PendingRequest) (*PendingResponse, error)
}

// unary is the method of a Server call: it decodes the request, puts the
// caller's SPIFFE ID in the context and calls the server.
func unary[Req, Resp any](name string, call func(Server, context.Context, *Req) (*Resp, error)) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		req := new(Req)
		if err := dec(req); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid: %v", err)
		}
		handler := func(ctx context.Context, req any) (any, error) {
			id, ok := grpccredentials.PeerIDFromContext(ctx)
			if !ok {
				return nil, Refuse(codes.Unauthenticated, "unauthorized_client", "no SPIFFE ID on the connection")
			}
			return call(srv.(Server), WithCaller(ctx, id), req.(*Req))
		}
		if interceptor == nil {
			return handler(ctx, req)
		}
		return interceptor(ctx, req, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + ServiceName + "/" + name}, handler)
	}}
}

// ServiceDesc describes the service for grpc.Server.RegisterService.
var ServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*Server)(nil),
	Methods: []grpc.MethodDesc{
		unary("Grant", Server.Grant),
		unary("Revoke", Server.Revoke),
		unary("Approve", Server.Approve),
		unary("Reject", Server.Reject),
		unary("List", Server.List),
		unary("Explain", Server.Explain),
		unary("Pending", Server.Pending),
	},
	Metadata: "cracha/access/v1",
}

// Register registers the server on s.
func Register(s *grpc.Server, srv Server) { s.RegisterService(&ServiceDesc, srv) }

type callerKey struct{}

// WithCaller is ctx carrying the caller's SPIFFE ID, as the transport
// verified it.
func WithCaller(ctx context.Context, id spiffeid.ID) context.Context {
	return context.WithValue(ctx, callerKey{}, id)
}

// CallerFrom is the caller's SPIFFE ID, and false when there is none.
func CallerFrom(ctx context.Context) (spiffeid.ID, bool) {
	id, ok := ctx.Value(callerKey{}).(spiffeid.ID)
	return id, ok && !id.IsZero()
}

// ReasonTrailer is the trailer a refusal's reason code travels in.
const ReasonTrailer = "cracha-reason"

// Refusal is a refused call: a gRPC code and the reason code.
type Refusal struct {
	Code   codes.Code
	Reason string
	Detail string
}

func (r *Refusal) Error() string { return r.Reason + ": " + r.Detail }

// GRPCStatus implements the interface grpc's status package reads.
func (r *Refusal) GRPCStatus() *status.Status { return status.New(r.Code, r.Error()) }

// Refuse makes a refusal.
func Refuse(code codes.Code, reason, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonInterceptor sets the reason trailer of every refusal.
func ReasonInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if r := (*Refusal)(nil); errors.As(err, &r) {
		_ = grpc.SetTrailer(ctx, metadata.Pairs(ReasonTrailer, r.Reason))
	}
	return resp, err
}
