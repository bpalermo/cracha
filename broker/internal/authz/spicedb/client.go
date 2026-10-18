package spicedb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	authzed "github.com/authzed/authzed-go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config is how Dial reaches SpiceDB.
type Config struct {
	// Endpoint is the gRPC address, host:port.
	Endpoint string
	// TokenFile holds the preshared key, which is read from the file and
	// sent as a bearer token on every call; it is never a flag value.
	TokenFile string
	// CAFile is a PEM bundle the server's certificate is verified with;
	// empty verifies it with the system roots.
	CAFile string
	// Insecure speaks plaintext gRPC and sends the token in the clear: for
	// a kind cluster only. It excludes CAFile.
	Insecure bool
}

// Dial opens a connection to SpiceDB and returns the store over it. The
// connection is lazy: a SpiceDB that is down fails the first call, not
// Dial. Close the store to close the connection.
func Dial(cfg Config, opts ...Option) (*Store, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("spicedb: endpoint is required")
	}
	if cfg.Insecure && cfg.CAFile != "" {
		return nil, errors.New("spicedb: insecure excludes a CA file")
	}
	token, err := readToken(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	transport, err := transportCredentials(cfg)
	if err != nil {
		return nil, err
	}
	client, err := authzed.NewClient(cfg.Endpoint,
		grpc.WithTransportCredentials(transport),
		grpc.WithPerRPCCredentials(bearerToken{token: token, insecure: cfg.Insecure}),
	)
	if err != nil {
		return nil, fmt.Errorf("spicedb: dial %s: %w", cfg.Endpoint, err)
	}
	s := New(client, client, opts...)
	s.closer = client
	return s, nil
}

// readToken reads the preshared key from its file.
func readToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("spicedb: token file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("spicedb: token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("spicedb: token file %s is empty", path)
	}
	return token, nil
}

// transportCredentials is how the connection is secured: plaintext when
// asked, else TLS against the CA file or the system roots.
func transportCredentials(cfg Config) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return insecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("spicedb: ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("spicedb: ca %s: no certificate in it", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}

// bearerToken sends the preshared key as a bearer token on every call. It
// implements credentials.PerRPCCredentials, and refuses a connection
// without transport security unless the insecure flag asked for one.
type bearerToken struct {
	token    string
	insecure bool
}

func (b bearerToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (b bearerToken) RequireTransportSecurity() bool {
	return !b.insecure
}
