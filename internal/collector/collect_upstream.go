package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/trace"
	"github.com/miekg/dns"
)

const (
	dnsPort          = "53"
	dnsRoot          = "."
	rootServerSuffix = ".root-servers.net."
	localUnbound     = "127.0.0.1"
	localUnboundPort = "5335"
	dnssecPositive   = "internetsociety.org."
	dnssecNegative   = "dnssec-failed.org."
)

type rootTarget struct {
	Name string
	IPv4 string
	IPv6 string
}

type recursiveResolver struct {
	Provider string
	Address  string
}

type publicIPProvider struct {
	Provider         string
	Address          string
	Name             string
	Type             uint16
	Family           int
	RecursionDesired bool
}

var rootTargets = []rootTarget{
	{Name: "e.root-servers.net.", IPv4: "192.203.230.10", IPv6: "2001:500:a8::e"},
	{Name: "j.root-servers.net.", IPv4: "192.58.128.30", IPv6: "2001:503:c27::2:30"},
}

var recursiveResolversV4 = []recursiveResolver{
	{Provider: "OpenDNS", Address: "208.67.222.222"},
	{Provider: "Google", Address: "8.8.8.8"},
}

var recursiveResolversV6 = []recursiveResolver{
	{Provider: "Google", Address: "2001:4860:4860::8888"},
	{Provider: "OpenDNS", Address: "2620:119:35::35"},
}

var publicIPv4Providers = []publicIPProvider{
	{Provider: "OpenDNS", Address: "208.67.222.222", Name: "myip.opendns.com.", Type: dns.TypeA, Family: 4, RecursionDesired: true},
	{Provider: "Google", Address: "216.239.32.10", Name: "o-o.myaddr.l.google.com.", Type: dns.TypeTXT, Family: 4, RecursionDesired: false},
}

var publicIPv6Providers = []publicIPProvider{
	{Provider: "Google", Address: "2001:4860:4802:32::a", Name: "o-o.myaddr.l.google.com.", Type: dns.TypeTXT, Family: 6, RecursionDesired: false},
	{Provider: "OpenDNS", Address: "2620:119:35::35", Name: "myip.opendns.com.", Type: dns.TypeAAAA, Family: 6, RecursionDesired: true},
}

type UpstreamCollector struct {
	ProbeTimeout time.Duration
}

func (c UpstreamCollector) Collect(ctx context.Context) model.UpstreamState {
	return model.UpstreamState{
		RootDNSV4:      c.probeRootDNS(ctx, "udp4"),
		RootDNSV6:      c.probeRootDNS(ctx, "udp6"),
		RecursiveDNSV4: c.probeRecursiveDNS(ctx, "udp4", dns.TypeA, recursiveResolversV4),
		RecursiveDNSV6: c.probeRecursiveDNS(ctx, "udp6", dns.TypeAAAA, recursiveResolversV6),
		DNSSEC:         c.probeDNSSEC(ctx),
		PublicIPv4:     c.observePublicIP(ctx, "udp4", publicIPv4Providers),
		PublicIPv6:     c.observePublicIP(ctx, "udp6", publicIPv6Providers),
	}
}

func (c UpstreamCollector) probeRootDNS(ctx context.Context, network string) model.DNSProbeResult {
	var failures []string

	for _, target := range rootTargets {
		probe := c.queryRootNS(ctx, network, target)
		emitProbeTrace(ctx, "root", network, target.Name, "", probe)
		if probe.OK() {
			return probe
		}
		failures = append(failures, formatProbeFailure(probe))
	}

	return model.DNSProbeResult{
		Status: model.DNSProbeStatusNetworkError,
		Detail: strings.Join(failures, "; "),
	}
}

func (c UpstreamCollector) queryRootNS(ctx context.Context, network string, target rootTarget) model.DNSProbeResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(dnsRoot), dns.TypeNS)
	msg.RecursionDesired = false

	host := target.IPv4
	if network == "udp6" {
		host = target.IPv6
	}

	answer, latency, err := c.exchange(ctx, network, host, dnsPort, msg)
	if err != nil {
		return model.DNSProbeResult{
			Name:    target.Name,
			Target:  host,
			Status:  classifyExchangeError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	status, detail := validateRootNSAnswer(answer)
	return model.DNSProbeResult{
		Name:    target.Name,
		Target:  host,
		Status:  status,
		Latency: latency,
		Detail:  detail,
	}
}

func (c UpstreamCollector) probeRecursiveDNS(ctx context.Context, network string, qtype uint16, resolvers []recursiveResolver) model.DNSProbeResult {
	var failures []string

	for _, resolver := range resolvers {
		for _, target := range rootTargets {
			probe := c.queryExpectedAddress(ctx, network, qtype, resolver, target)
			emitProbeTrace(ctx, "recursive", network, target.Name, resolver.Provider, probe)
			if probe.OK() {
				return probe
			}
			failures = append(failures, formatProbeFailure(probe))
		}
	}

	return model.DNSProbeResult{
		Status: model.DNSProbeStatusNetworkError,
		Detail: strings.Join(failures, "; "),
	}
}

func (c UpstreamCollector) queryExpectedAddress(ctx context.Context, network string, qtype uint16, resolver recursiveResolver, target rootTarget) model.DNSProbeResult {
	msg := new(dns.Msg)
	msg.SetQuestion(target.Name, qtype)
	msg.RecursionDesired = true

	expected := target.IPv4
	if qtype == dns.TypeAAAA {
		expected = target.IPv6
	}

	answer, latency, err := c.exchange(ctx, network, resolver.Address, dnsPort, msg)
	if err != nil {
		return model.DNSProbeResult{
			Name:    fmt.Sprintf("%s via %s", target.Name, resolver.Provider),
			Target:  resolver.Address,
			Status:  classifyExchangeError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	status, detail := validateExpectedAddressAnswer(answer, qtype, expected)
	return model.DNSProbeResult{
		Name:    fmt.Sprintf("%s via %s", target.Name, resolver.Provider),
		Target:  resolver.Address,
		Status:  status,
		Latency: latency,
		Detail:  detail,
	}
}

func (c UpstreamCollector) observePublicIP(ctx context.Context, network string, providers []publicIPProvider) model.PublicIPObservation {
	var failures []string

	for _, provider := range providers {
		observation := c.queryPublicIP(ctx, network, provider)
		emitObservationTrace(ctx, network, provider.Provider, observation)
		if observation.OK() {
			return observation
		}
		failures = append(failures, formatObservationFailure(observation))
	}

	return model.PublicIPObservation{
		Detail: strings.Join(failures, "; "),
	}
}

func (c UpstreamCollector) probeDNSSEC(ctx context.Context) model.DNSSECProbeResult {
	positive := c.queryDNSSECPositive(ctx)
	negative := c.queryDNSSECNegative(ctx)
	emitDNSSECTrace(ctx, "dnssec_positive", positive)
	emitDNSSECTrace(ctx, "dnssec_negative", negative)

	return model.DNSSECProbeResult{
		Positive: positive,
		Negative: negative,
	}
}

func (c UpstreamCollector) queryDNSSECPositive(ctx context.Context) model.DNSSECProbeAttempt {
	msg := new(dns.Msg)
	msg.SetQuestion(dnssecPositive, dns.TypeA)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, true)

	answer, latency, err := c.exchange(ctx, "udp4", localUnbound, localUnboundPort, msg)
	if err != nil {
		return model.DNSSECProbeAttempt{
			Name:    dnssecPositive,
			Target:  net.JoinHostPort(localUnbound, localUnboundPort),
			Status:  classifyDNSSECError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	attempt := model.DNSSECProbeAttempt{
		Name:    dnssecPositive,
		Target:  net.JoinHostPort(localUnbound, localUnboundPort),
		Latency: latency,
	}
	attempt.Status, attempt.Rcode, attempt.AD, attempt.Detail = validateDNSSECPositiveAnswer(answer)
	return attempt
}

func (c UpstreamCollector) queryDNSSECNegative(ctx context.Context) model.DNSSECProbeAttempt {
	msg := new(dns.Msg)
	msg.SetQuestion(dnssecNegative, dns.TypeA)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, true)

	answer, latency, err := c.exchange(ctx, "udp4", localUnbound, localUnboundPort, msg)
	if err != nil {
		return model.DNSSECProbeAttempt{
			Name:    dnssecNegative,
			Target:  net.JoinHostPort(localUnbound, localUnboundPort),
			Status:  classifyDNSSECError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	attempt := model.DNSSECProbeAttempt{
		Name:    dnssecNegative,
		Target:  net.JoinHostPort(localUnbound, localUnboundPort),
		Latency: latency,
	}
	attempt.Status, attempt.Rcode, attempt.AD, attempt.Detail = validateDNSSECNegativeAnswer(answer)
	return attempt
}

func (c UpstreamCollector) queryPublicIP(ctx context.Context, network string, provider publicIPProvider) model.PublicIPObservation {
	msg := new(dns.Msg)
	msg.SetQuestion(provider.Name, provider.Type)
	msg.RecursionDesired = provider.RecursionDesired

	answer, latency, err := c.exchange(ctx, network, provider.Address, dnsPort, msg)
	if err != nil {
		return model.PublicIPObservation{
			Provider: provider.Provider,
			Target:   provider.Address,
			Latency:  latency,
			Detail:   err.Error(),
		}
	}

	ip, detail := extractObservedIP(answer, provider.Type, provider.Family)
	return model.PublicIPObservation{
		Provider: provider.Provider,
		Target:   provider.Address,
		IP:       ip,
		Latency:  latency,
		Detail:   detail,
	}
}

func (c UpstreamCollector) exchange(ctx context.Context, network, host, port string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	probeCtx, cancel := context.WithTimeout(ctx, c.ProbeTimeout)
	defer cancel()

	client := &dns.Client{
		Net:     network,
		Timeout: c.ProbeTimeout,
	}

	answer, latency, err := client.ExchangeContext(probeCtx, msg, net.JoinHostPort(host, port))
	return answer, latency, err
}

func validateRootNSAnswer(answer *dns.Msg) (model.DNSProbeStatus, string) {
	status, detail := validateDNSMessage(answer)
	if status != model.DNSProbeStatusOK {
		return status, detail
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
			return model.DNSProbeStatusOK, ""
		}
	}

	return model.DNSProbeStatusUnexpectedAnswer, "response contains no root-server NS records (possible interception)"
}

func validateExpectedAddressAnswer(answer *dns.Msg, qtype uint16, expected string) (model.DNSProbeStatus, string) {
	status, detail := validateDNSMessage(answer)
	if status != model.DNSProbeStatusOK {
		return status, detail
	}
	if len(answer.Answer) == 0 {
		return model.DNSProbeStatusUnexpectedAnswer, "no answers"
	}

	var got []string
	for _, rr := range answer.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if qtype != dns.TypeA {
				continue
			}
			ip := record.A.String()
			got = append(got, ip)
			if ip == expected {
				return model.DNSProbeStatusOK, ""
			}
		case *dns.AAAA:
			if qtype != dns.TypeAAAA {
				continue
			}
			ip := record.AAAA.String()
			got = append(got, ip)
			if ip == expected {
				return model.DNSProbeStatusOK, ""
			}
		}
	}

	if len(got) == 0 {
		return model.DNSProbeStatusUnexpectedAnswer, "no matching address answers"
	}
	return model.DNSProbeStatusUnexpectedAnswer, fmt.Sprintf("expected %s, got %s", expected, strings.Join(got, ", "))
}

func extractObservedIP(answer *dns.Msg, qtype uint16, family int) (string, string) {
	status, detail := validateDNSMessage(answer)
	if status != model.DNSProbeStatusOK {
		return "", detail
	}
	if len(answer.Answer) == 0 {
		return "", "no answers"
	}

	for _, rr := range answer.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				return record.A.String(), ""
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				return record.AAAA.String(), ""
			}
		case *dns.TXT:
			if qtype != dns.TypeTXT {
				continue
			}
			for _, value := range record.Txt {
				if ip := net.ParseIP(strings.Trim(strings.TrimSpace(value), `"`)); ip != nil && matchesFamily(ip, family) {
					return ip.String(), ""
				}
			}
		}
	}

	return "", "no public IP answer"
}

func validateDNSSECPositiveAnswer(answer *dns.Msg) (model.DNSSECProbeStatus, string, bool, string) {
	if answer == nil {
		return model.DNSSECProbeStatusUnexpectedFailure, "", false, "nil response"
	}
	rcode := dns.RcodeToString[answer.Rcode]
	if !answer.Response {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "response missing QR bit"
	}
	if answer.Rcode != dns.RcodeSuccess {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, fmt.Sprintf("expected NOERROR, got %s", rcode)
	}
	if len(answer.Answer) == 0 {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "no A answers"
	}
	if !answer.AuthenticatedData {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, false, "missing AD bit"
	}
	for _, rr := range answer.Answer {
		if _, ok := rr.(*dns.A); ok {
			return model.DNSSECProbeStatusOK, rcode, true, ""
		}
	}
	return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "no A answers"
}

func validateDNSSECNegativeAnswer(answer *dns.Msg) (model.DNSSECProbeStatus, string, bool, string) {
	if answer == nil {
		return model.DNSSECProbeStatusUnexpectedFailure, "", false, "nil response"
	}
	rcode := dns.RcodeToString[answer.Rcode]
	if !answer.Response {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "response missing QR bit"
	}
	if answer.Rcode == dns.RcodeServerFailure {
		return model.DNSSECProbeStatusOK, rcode, answer.AuthenticatedData, ""
	}
	if answer.Rcode == dns.RcodeSuccess {
		return model.DNSSECProbeStatusUnexpectedSuccess, rcode, answer.AuthenticatedData, "expected SERVFAIL, got NOERROR"
	}
	return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, fmt.Sprintf("expected SERVFAIL, got %s", rcode)
}

func matchesFamily(ip net.IP, family int) bool {
	switch family {
	case 4:
		return ip.To4() != nil
	case 6:
		return ip.To4() == nil && ip.To16() != nil
	default:
		return ip != nil
	}
}

func validateDNSMessage(answer *dns.Msg) (model.DNSProbeStatus, string) {
	if answer == nil {
		return model.DNSProbeStatusMalformed, "nil response"
	}
	if !answer.Response {
		return model.DNSProbeStatusMalformed, "response missing QR bit"
	}

	switch answer.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeRefused:
		return model.DNSProbeStatusRefused, "dns rcode=REFUSED"
	case dns.RcodeServerFailure:
		return model.DNSProbeStatusServfail, "dns rcode=SERVFAIL"
	case dns.RcodeNameError:
		return model.DNSProbeStatusNXDomain, "dns rcode=NXDOMAIN"
	default:
		return model.DNSProbeStatusMalformed, fmt.Sprintf("dns rcode=%d", answer.Rcode)
	}

	if len(answer.Answer) == 0 && len(answer.Ns) == 0 && len(answer.Extra) == 0 {
		return model.DNSProbeStatusMalformed, "empty response"
	}

	return model.DNSProbeStatusOK, ""
}

func classifyExchangeError(err error) model.DNSProbeStatus {
	if err == nil {
		return model.DNSProbeStatusOK
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.DNSProbeStatusTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.DNSProbeStatusTimeout
	}
	return model.DNSProbeStatusNetworkError
}

func classifyDNSSECError(err error) model.DNSSECProbeStatus {
	if err == nil {
		return model.DNSSECProbeStatusOK
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.DNSSECProbeStatusTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.DNSSECProbeStatusTimeout
	}
	return model.DNSSECProbeStatusNetworkError
}

func formatProbeFailure(result model.DNSProbeResult) string {
	label := result.Name
	if label == "" {
		label = result.Target
	}
	if label == "" {
		label = "probe"
	}
	if result.Detail == "" {
		return fmt.Sprintf("%s: %s", label, result.Status)
	}
	return fmt.Sprintf("%s: %s (%s)", label, result.Status, result.Detail)
}

func formatObservationFailure(observation model.PublicIPObservation) string {
	label := observation.Provider
	if observation.Target != "" {
		label = fmt.Sprintf("%s via %s", label, observation.Target)
	}
	if observation.Detail == "" {
		return label
	}
	return fmt.Sprintf("%s: %s", label, observation.Detail)
}

func emitProbeTrace(ctx context.Context, kind, network, target, provider string, probe model.DNSProbeResult) {
	trace.EmitProbeResult(ctx, trace.ProbeResultFields{
		Kind:      kind,
		Family:    familyFromNetwork(network),
		Target:    target,
		Provider:  provider,
		Status:    probe.Status.String(),
		Latency:   probe.Latency,
		Responder: probe.Target,
		Detail:    probe.Detail,
	})
}

func emitObservationTrace(ctx context.Context, network, provider string, observation model.PublicIPObservation) {
	trace.EmitProbeResult(ctx, trace.ProbeResultFields{
		Kind:     "public_ip",
		Family:   familyFromNetwork(network),
		Provider: provider,
		Target:   observation.Target,
		Status:   map[bool]string{true: "ok", false: "failed"}[observation.OK()],
		Latency:  observation.Latency,
		Detail:   observation.Detail,
		IP:       observation.IP,
	})
}

func emitDNSSECTrace(ctx context.Context, kind string, attempt model.DNSSECProbeAttempt) {
	trace.EmitProbeResult(ctx, trace.ProbeResultFields{
		Kind:     kind,
		Family:   "local",
		Target:   attempt.Target,
		Status:   attempt.Status.String(),
		Latency:  attempt.Latency,
		Detail:   attempt.Detail,
		Provider: "unbound",
	})
}

func familyFromNetwork(network string) string {
	switch network {
	case "udp4", "tcp4":
		return "ipv4"
	case "udp6", "tcp6":
		return "ipv6"
	default:
		return network
	}
}
