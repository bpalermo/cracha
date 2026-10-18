package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// workloadAPI is the broker's one connection to the SPIFFE Workload API
// (design 4.1: the only thing the broker asks of the identity issuer) and
// the two sources over it: the X.509 source, the broker's own SVID and the
// X.509 bundles it serves mTLS with (design 6.5), and the JWT source, the
// bundles the workloads' JWT-SVIDs are verified against. Both follow the
// API's rotation; each is its own stream on the shared connection.
type workloadAPI struct {
	client *workloadapi.Client
	x509   *workloadapi.X509Source
	jwt    *workloadapi.JWTSource
}

// connectWorkloadAPI dials the Workload API at addr (for example
// unix:///run/spire/sockets/agent.sock) and opens both sources. It blocks
// until the first SVID and the first bundles arrive, or ctx ends.
func connectWorkloadAPI(ctx context.Context, addr string) (*workloadAPI, error) {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(addr))
	if err != nil {
		return nil, err
	}
	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(client))
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("x509 source: %w", err)
	}
	jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClient(client))
	if err != nil {
		_ = x509Source.Close()
		_ = client.Close()
		return nil, fmt.Errorf("jwt source: %w", err)
	}
	return &workloadAPI{client: client, x509: x509Source, jwt: jwtSource}, nil
}

// Close closes both sources and the connection.
func (w *workloadAPI) Close() error {
	return errors.Join(w.jwt.Close(), w.x509.Close(), w.client.Close())
}
