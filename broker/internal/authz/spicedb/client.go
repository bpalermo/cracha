package spicedb

import (
	"github.com/bpalermo/cracha/common/spicedb/conn"
)

// Dial opens a connection to SpiceDB through its gateway, over SPIFFE mTLS
// with the broker's own X.509-SVID (common/spicedb/conn; design 6.4), and
// returns the store over it. The broker holds no SpiceDB key: the gateway
// admits its SPIFFE ID to the read methods only and adds the key itself.
// The connection is lazy: a gateway that is down fails the first call, not
// Dial. Close the store to close the connection.
func Dial(cfg conn.Config, opts ...Option) (*Store, error) {
	client, err := conn.Dial(cfg)
	if err != nil {
		return nil, err
	}
	s := New(client, client, opts...)
	s.closer = client
	return s, nil
}
