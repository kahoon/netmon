package rpc

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	netmonv1connect "github.com/kahoon/netmon/proto/netmon/v1/netmonv1connect"
	"golang.org/x/net/http2"
)

const baseURL = "http://netmond"

func NewClient(socketPath string) netmonv1connect.NetmonServiceClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	return netmonv1connect.NewNetmonServiceClient(
		&http.Client{Transport: transport},
		baseURL,
		connect.WithSendCompression("gzip"),
	)
}
