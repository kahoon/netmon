package collector

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// exchange sends a DNS message and returns the response, latency, and any
// error. It is shared by all collectors that need to make DNS queries.
func exchange(ctx context.Context, timeout time.Duration, network, host, port string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &dns.Client{
		Net:     network,
		Timeout: timeout,
	}

	answer, latency, err := client.ExchangeContext(probeCtx, msg, net.JoinHostPort(host, port))
	return answer, latency, err
}
