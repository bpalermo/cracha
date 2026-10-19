// Command grpc_health_probe asks a gRPC server's health service whether it
// is serving, for the probes of the spicedb image (//bazel/spicedb:image),
// whose SpiceDB the chart serves on the pod's loopback only, out of reach of
// the kubelet's native gRPC probe. It takes the -addr and -connect-timeout
// and -rpc-timeout flags of grpc-ecosystem/grpc-health-probe, which
// upstream's image carries, and nothing else: plaintext, the overall service.
// It exits 0 when the server answers SERVING and 1 otherwise.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := flag.String("addr", "", "the server's address, host:port")
	connectTimeout := flag.Duration("connect-timeout", time.Second, "how long to wait for the connection")
	rpcTimeout := flag.Duration("rpc-timeout", time.Second, "how long to wait for the answer")
	flag.Parse()
	if err := probe(*addr, *connectTimeout+*rpcTimeout); err != nil {
		fmt.Fprintln(os.Stderr, "grpc_health_probe:", err)
		os.Exit(1)
	}
}

func probe(addr string, timeout time.Duration) error {
	if addr == "" {
		return fmt.Errorf("-addr is required")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return fmt.Errorf("health check of %s: %w", addr, err)
	}
	if s := resp.GetStatus(); s != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("%s is %s", addr, s)
	}
	return nil
}
