package api

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Client calls the service over a connection.
type Client struct {
	conn grpc.ClientConnInterface
}

// NewClient makes a client over a connection the caller dialed (with its
// SVID: cracha-access accepts nothing else).
func NewClient(conn grpc.ClientConnInterface) *Client { return &Client{conn: conn} }

// CallError is a failed call with the reason code the server gave, when
// it gave one.
type CallError struct {
	Reason string
	Err    error
}

func (e *CallError) Error() string { return e.Err.Error() }
func (e *CallError) Unwrap() error { return e.Err }

func invoke[Resp any](ctx context.Context, c *Client, method string, req any) (*Resp, error) {
	resp := new(Resp)
	var trailer metadata.MD
	err := c.conn.Invoke(ctx, "/"+ServiceName+"/"+method, req, resp, grpc.CallContentSubtype(Codec{}.Name()), grpc.Trailer(&trailer))
	if err != nil {
		reason := ""
		if v := trailer.Get(ReasonTrailer); len(v) > 0 {
			reason = v[0]
		}
		return nil, &CallError{Reason: reason, Err: err}
	}
	return resp, nil
}

// Grant calls Grant.
func (c *Client) Grant(ctx context.Context, req *GrantRequest) (*WriteResponse, error) {
	return invoke[WriteResponse](ctx, c, "Grant", req)
}

// Revoke calls Revoke.
func (c *Client) Revoke(ctx context.Context, req *RevokeRequest) (*WriteResponse, error) {
	return invoke[WriteResponse](ctx, c, "Revoke", req)
}

// Approve calls Approve.
func (c *Client) Approve(ctx context.Context, req *DecideRequest) (*WriteResponse, error) {
	return invoke[WriteResponse](ctx, c, "Approve", req)
}

// Reject calls Reject.
func (c *Client) Reject(ctx context.Context, req *DecideRequest) (*WriteResponse, error) {
	return invoke[WriteResponse](ctx, c, "Reject", req)
}

// List calls List.
func (c *Client) List(ctx context.Context, req *ListRequest) (*ListResponse, error) {
	return invoke[ListResponse](ctx, c, "List", req)
}

// Explain calls Explain.
func (c *Client) Explain(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error) {
	return invoke[ExplainResponse](ctx, c, "Explain", req)
}

// Pending calls Pending.
func (c *Client) Pending(ctx context.Context, req *PendingRequest) (*PendingResponse, error) {
	return invoke[PendingResponse](ctx, c, "Pending", req)
}
