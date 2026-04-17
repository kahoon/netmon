package collector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kahoon/netmon/internal/model"
	"github.com/miekg/dns"
)

const (
	dnsPort          = "53"
	dnsRoot          = "."
	rootServerSuffix = ".root-servers.net."
)

type UpstreamCollector struct {
	RootServersV4 []string
	RootServersV6 []string

	PublicIPResolver string
	PublicIPName     string

	ProbeTimeout time.Duration
}

func (c UpstreamCollector) Collect(ctx context.Context) model.UpstreamState {
	return model.UpstreamState{
		ExternalDNSV4: c.probeExternalDNS(ctx, "udp4", c.RootServersV4),
		ExternalDNSV6: c.probeExternalDNS(ctx, "udp6", c.RootServersV6),
		PublicIPv4:    c.queryPublicIPv4(ctx),
	}
}

func (c UpstreamCollector) probeExternalDNS(ctx context.Context, network string, targets []string) model.DNSProbeResult {
	var errors []string

	for _, target := range targets {
		if err := c.queryRootNS(ctx, target, network); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", target, err))
			continue
		}
		return model.DNSProbeResult{Target: target}
	}
	return model.DNSProbeResult{Error: strings.Join(errors, "; ")}
}

func (c UpstreamCollector) queryRootNS(ctx context.Context, target, network string) error {
	probeCtx, cancel := context.WithTimeout(ctx, c.ProbeTimeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(dnsRoot), dns.TypeNS)
	msg.RecursionDesired = false
	client := &dns.Client{
		Net:     network,
		Timeout: c.ProbeTimeout,
	}
	answer, _, err := client.ExchangeContext(probeCtx, msg, net.JoinHostPort(target, dnsPort))
	if err != nil {
		return err
	}
	return validateRootNSAnswer(answer)
}

func validateRootNSAnswer(answer *dns.Msg) error {
	if answer == nil {
		return fmt.Errorf("nil response")
	}
	if !answer.Response {
		return fmt.Errorf("response missing QR bit")
	}
	if answer.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dns rcode=%d", answer.Rcode)
	}
	if len(answer.Answer) == 0 && len(answer.Ns) == 0 && len(answer.Extra) == 0 {
		return fmt.Errorf("empty response")
	}

	for _, rr := range append(append([]dns.RR{}, answer.Answer...), answer.Ns...) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		if ns.Hdr.Name != dnsRoot {
			continue
		}
		if strings.HasSuffix(ns.Ns, rootServerSuffix) {
			return nil
		}
	}
	return fmt.Errorf("response contains no root-server NS records (possible interception)")
}

func (c UpstreamCollector) queryPublicIPv4(ctx context.Context) model.PublicIPResult {
	probeCtx, cancel := context.WithTimeout(ctx, c.ProbeTimeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(c.PublicIPName), dns.TypeA)
	msg.RecursionDesired = true
	client := &dns.Client{
		Net:     "udp4",
		Timeout: c.ProbeTimeout,
	}
	answer, _, err := client.ExchangeContext(probeCtx, msg, model.EnsurePort(c.PublicIPResolver, dnsPort))
	if err != nil {
		return model.PublicIPResult{Error: err.Error()}
	}
	ipv4, err := extractPublicIPv4(answer)
	if err != nil {
		return model.PublicIPResult{Error: err.Error()}
	}
	return model.PublicIPResult{IPv4: ipv4}
}

func extractPublicIPv4(answer *dns.Msg) (string, error) {
	if answer == nil {
		return "", fmt.Errorf("nil response")
	}
	if !answer.Response {
		return "", fmt.Errorf("response missing QR bit")
	}
	if answer.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("dns rcode=%d", answer.Rcode)
	}
	if len(answer.Answer) == 0 {
		return "", fmt.Errorf("no IPv4 answers")
	}

	for _, rr := range answer.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 answer")
}
