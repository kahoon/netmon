package model

import "net"

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

type UpstreamState struct {
	ExternalDNSV4 DNSProbeResult
	ExternalDNSV6 DNSProbeResult
	PublicIPv4    PublicIPResult
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
	Target string
	Error  string
}

func (r DNSProbeResult) OK() bool {
	return r.Target != ""
}

type PublicIPResult struct {
	IPv4  string
	Error string
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
