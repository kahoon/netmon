package model

import (
	"net"
	"strings"
	"time"
)

type Severity int

const (
	SeverityOK Severity = iota
	SeverityInfo
	SeverityWarn
	SeverityCrit
)

func (s Severity) String() string {
	switch s {
	case SeverityCrit:
		return "CRIT"
	case SeverityWarn:
		return "WARN"
	case SeverityInfo:
		return "INFO"
	default:
		return "OK"
	}
}

func (s Severity) Priority() string {
	switch s {
	case SeverityCrit:
		return "high"
	case SeverityWarn:
		return "default"
	default:
		return "low"
	}
}

func (s Severity) Tags() string {
	switch s {
	case SeverityCrit:
		return "warning,network,dns"
	case SeverityWarn:
		return "network_wired,dns"
	default:
		return "white_check_mark,network,dns"
	}
}

type CheckResult struct {
	Key      string
	Label    string
	Severity Severity
	Summary  string
	Detail   string
}

func (r CheckResult) Equal(other CheckResult) bool {
	return r.Key == other.Key &&
		r.Label == other.Label &&
		r.Severity == other.Severity &&
		r.Summary == other.Summary &&
		r.Detail == other.Detail
}

type CheckSet map[string]CheckResult

type InterfaceState struct {
	LinkIndex int
	IfName    string
	LinkUp    bool
	OperState string
	ULA       []string
	GUA       []string
	UsableGUA []string
}

type ListenerState struct {
	DNS53TCP        SocketProbe
	DNS53UDP        SocketProbe
	Resolver5335TCP SocketProbe
	Resolver5335UDP SocketProbe
}

type DNSProbeStatus string

const (
	DNSProbeStatusOK               DNSProbeStatus = "ok"
	DNSProbeStatusTimeout          DNSProbeStatus = "timeout"
	DNSProbeStatusNetworkError     DNSProbeStatus = "network_error"
	DNSProbeStatusRefused          DNSProbeStatus = "refused"
	DNSProbeStatusServfail         DNSProbeStatus = "servfail"
	DNSProbeStatusNXDomain         DNSProbeStatus = "nxdomain"
	DNSProbeStatusMalformed        DNSProbeStatus = "malformed"
	DNSProbeStatusUnexpectedAnswer DNSProbeStatus = "unexpected_answer"
)

func (s DNSProbeStatus) String() string {
	if s == "" {
		return string(DNSProbeStatusMalformed)
	}
	return string(s)
}

type UpstreamState struct {
	RootDNSV4      DNSProbeResult
	RootDNSV6      DNSProbeResult
	RecursiveDNSV4 DNSProbeResult
	RecursiveDNSV6 DNSProbeResult
	DNSSEC         DNSSECProbeResult
	PublicIPv4     PublicIPObservation
	PublicIPv6     PublicIPObservation
}

type SystemState struct {
	Interface InterfaceState
	Listeners ListenerState
	Upstream  UpstreamState
}

type SocketProbe struct {
	Loopback    []string
	NonLoopback []string
}

func (p SocketProbe) HasLoopback() bool {
	return len(p.Loopback) > 0
}

func (p SocketProbe) HasNonLoopback() bool {
	return len(p.NonLoopback) > 0
}

func (p SocketProbe) HasNonLoopbackIPv4() bool {
	return hasFamily(p.NonLoopback, 4)
}

func (p SocketProbe) HasNonLoopbackIPv6() bool {
	return hasFamily(p.NonLoopback, 6)
}

type DNSProbeResult struct {
	Name    string
	Target  string
	Status  DNSProbeStatus
	Latency time.Duration
	Detail  string
}

func (r DNSProbeResult) OK() bool {
	return r.Status == DNSProbeStatusOK
}

func (r DNSProbeResult) Summary() string {
	if r.OK() {
		if r.Name != "" {
			return r.Name
		}
		if r.Target != "" {
			return r.Target
		}
		return "ok"
	}

	parts := []string{r.Status.String()}
	if r.Name != "" {
		parts = append(parts, "via "+r.Name)
	}
	if r.Detail != "" {
		parts = append(parts, r.Detail)
	}
	return strings.Join(parts, "; ")
}

type PublicIPObservation struct {
	Provider string
	Target   string
	IP       string
	Latency  time.Duration
	Detail   string
}

func (o PublicIPObservation) OK() bool {
	return o.IP != ""
}

func (o PublicIPObservation) Summary() string {
	if o.OK() {
		parts := []string{o.IP}
		if o.Provider != "" {
			parts = append(parts, "via "+o.Provider)
		}
		return strings.Join(parts, "; ")
	}

	parts := []string{}
	if o.Provider != "" {
		parts = append(parts, o.Provider)
	}
	if o.Detail != "" {
		parts = append(parts, o.Detail)
	}
	return strings.Join(parts, "; ")
}

type DNSSECProbeStatus string

const (
	DNSSECProbeStatusOK                DNSSECProbeStatus = "ok"
	DNSSECProbeStatusUnexpectedSuccess DNSSECProbeStatus = "unexpected_success"
	DNSSECProbeStatusUnexpectedFailure DNSSECProbeStatus = "unexpected_failure"
	DNSSECProbeStatusTimeout           DNSSECProbeStatus = "timeout"
	DNSSECProbeStatusNetworkError      DNSSECProbeStatus = "network_error"
)

func (s DNSSECProbeStatus) String() string {
	if s == "" {
		return string(DNSSECProbeStatusUnexpectedFailure)
	}
	return string(s)
}

type DNSSECProbeAttempt struct {
	Name    string
	Target  string
	Status  DNSSECProbeStatus
	Rcode   string
	AD      bool
	Latency time.Duration
	Detail  string
}

func (a DNSSECProbeAttempt) OK() bool {
	return a.Status == DNSSECProbeStatusOK
}

func (a DNSSECProbeAttempt) Summary() string {
	if a.OK() {
		parts := []string{"ok"}
		if a.Name != "" {
			parts = append(parts, a.Name)
		}
		if a.AD {
			parts = append(parts, "ad=true")
		}
		return strings.Join(parts, "; ")
	}

	parts := []string{a.Status.String()}
	if a.Rcode != "" {
		parts = append(parts, "rcode="+a.Rcode)
	}
	if a.Detail != "" {
		parts = append(parts, a.Detail)
	}
	return strings.Join(parts, "; ")
}

type DNSSECProbeResult struct {
	Positive DNSSECProbeAttempt
	Negative DNSSECProbeAttempt
}

func hasFamily(bindings []string, family int) bool {
	for _, binding := range bindings {
		host, _, err := net.SplitHostPort(binding)
		if err != nil {
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}

		switch family {
		case 4:
			if ip.To4() != nil {
				return true
			}
		case 6:
			if ip.To4() == nil && ip.To16() != nil {
				return true
			}
		}
	}

	return false
}
