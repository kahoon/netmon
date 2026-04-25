package model

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	checkInterfaceCollection = "interface-collection"
	checkInterfaceOper       = "interface-oper"
	checkExpectedULA         = "expected-ula"
	checkUsableGUA           = "usable-gua"
	checkListenerCollection  = "listener-collection"
	checkDNS53TCP            = "dns53-tcp"
	checkDNS53UDP            = "dns53-udp"
	checkResolver5335TCP     = "resolver5335-tcp"
	checkResolver5335UDP     = "resolver5335-udp"
	checkExpose5335TCP       = "resolver5335-exposed-tcp"
	checkExpose5335UDP       = "resolver5335-exposed-udp"
	checkExternalDNSV4       = "external-dns-v4"
	checkExternalDNSV6       = "external-dns-v6"
	checkDNSSEC              = "dnssec-validation"
	checkPiHoleDNSV4         = "pihole-dns-v4"
	checkPiHoleDNSV6         = "pihole-dns-v6"
	checkPiHoleBlocking      = "pihole-blocking"
	checkPiHoleUpstreams     = "pihole-upstreams"
	checkPiHoleGravity       = "pihole-gravity"
	checkTailscale           = "tailscale-connected"
)

var checkOrder = []string{
	checkInterfaceCollection,
	checkInterfaceOper,
	checkExpectedULA,
	checkUsableGUA,
	checkListenerCollection,
	checkDNS53TCP,
	checkDNS53UDP,
	checkResolver5335TCP,
	checkResolver5335UDP,
	checkExpose5335TCP,
	checkExpose5335UDP,
	checkExternalDNSV4,
	checkExternalDNSV6,
	checkDNSSEC,
	checkPiHoleDNSV4,
	checkPiHoleDNSV6,
	checkPiHoleBlocking,
	checkPiHoleUpstreams,
	checkPiHoleGravity,
	checkTailscale,
}

func EvaluateChecks(expectedULA string, state SystemState) CheckSet {
	checks := make(CheckSet, len(checkOrder))
	addCheck(checks, interfaceCollectionCheck(state.Interface))
	addCheck(checks, interfaceOperationalCheck(state))
	addCheck(checks, expectedULACheck(expectedULA, state))
	addCheck(checks, usableGUACheck(state))
	addCheck(checks, listenerCollectionCheck(state.Listeners))
	addCheck(checks, dnsCoverageCheck(checkDNS53TCP, "53/tcp", state.Listeners.DNS53TCP))
	addCheck(checks, dnsCoverageCheck(checkDNS53UDP, "53/udp", state.Listeners.DNS53UDP))
	addCheck(checks, localhostCheck(checkResolver5335TCP, "5335/tcp", state.Listeners.Resolver5335TCP))
	addCheck(checks, localhostCheck(checkResolver5335UDP, "5335/udp", state.Listeners.Resolver5335UDP))
	addCheck(checks, exposureCheck(checkExpose5335TCP, "5335/tcp", state.Listeners.Resolver5335TCP))
	addCheck(checks, exposureCheck(checkExpose5335UDP, "5335/udp", state.Listeners.Resolver5335UDP))
	addCheck(checks, externalDNSCheck(checkExternalDNSV4, "IPv4", state.Upstream.RootDNSV4, state.Upstream.RecursiveDNSV4))
	addCheck(checks, externalDNSCheck(checkExternalDNSV6, "IPv6", state.Upstream.RootDNSV6, state.Upstream.RecursiveDNSV6))
	addCheck(checks, dnssecValidationCheck(state.Unbound.DNSSEC))
	addCheck(checks, piholeDNSCheck(checkPiHoleDNSV4, "IPv4", state.PiHole.DNSV4))
	addCheck(checks, piholeDNSCheck(checkPiHoleDNSV6, "IPv6", state.PiHole.DNSV6))
	addCheck(checks, piholeBlockingCheck(state.PiHole.Status))
	addCheck(checks, piholeUpstreamsCheck(state.PiHole.Upstreams))
	addCheck(checks, piholeGravityCheck(state.PiHole.Gravity))
	addCheck(checks, tailscaleConnectedCheck(state.Tailscale))
	return checks
}

func CurrentOverallSeverity(checks CheckSet) Severity {
	severity := SeverityInfo
	for _, result := range checks {
		if result.Severity > severity {
			severity = result.Severity
		}
	}

	if severity < SeverityCrit &&
		checks[checkExternalDNSV4].Severity >= SeverityWarn &&
		checks[checkExternalDNSV6].Severity >= SeverityWarn {
		return SeverityCrit
	}

	return severity
}

func CurrentHealthSeverity(checks CheckSet) Severity {
	severity := SeverityOK
	for _, result := range checks {
		if result.Severity > severity {
			severity = result.Severity
		}
	}

	if severity < SeverityCrit &&
		checks[checkExternalDNSV4].Severity >= SeverityWarn &&
		checks[checkExternalDNSV6].Severity >= SeverityWarn {
		return SeverityCrit
	}

	return severity
}

func CheckOrder() []string {
	return append([]string{}, checkOrder...)
}

func interfaceOperationalCheck(state SystemState) CheckResult {
	result := CheckResult{
		Key:      checkInterfaceOper,
		Label:    "interface operational",
		Severity: SeverityOK,
	}

	if state.Interface.IfName == "" || state.Interface.OperState == "up" {
		return result
	}

	result.Severity = SeverityCrit
	result.Summary = fmt.Sprintf("interface %s operstate %s", state.Interface.IfName, state.Interface.OperState)
	return result
}

func interfaceCollectionCheck(state InterfaceState) CheckResult {
	result := CheckResult{
		Key:      checkInterfaceCollection,
		Label:    "interface collection",
		Severity: SeverityOK,
	}

	if state.CollectionError == "" {
		return result
	}

	result.Severity = SeverityWarn
	result.Summary = "interface collection failed"
	result.Detail = state.CollectionError
	return result
}

func addCheck(checks CheckSet, result CheckResult) {
	checks[result.Key] = result
}

func expectedULACheck(expectedULA string, state SystemState) CheckResult {
	result := CheckResult{
		Key:      checkExpectedULA,
		Label:    "expected ULA",
		Severity: SeverityOK,
	}

	if expectedULA == "" || slices.Contains(state.Interface.ULA, expectedULA) {
		return result
	}

	result.Severity = SeverityCrit
	result.Summary = "expected ULA missing"
	result.Detail = fmt.Sprintf("wanted %s", expectedULA)
	return result
}

func usableGUACheck(state SystemState) CheckResult {
	result := CheckResult{
		Key:      checkUsableGUA,
		Label:    "usable global IPv6",
		Severity: SeverityOK,
	}

	if len(state.Interface.UsableGUA) > 0 {
		return result
	}

	result.Severity = SeverityWarn
	result.Summary = "no usable global IPv6"
	return result
}

func listenerCollectionCheck(state ListenerState) CheckResult {
	result := CheckResult{
		Key:      checkListenerCollection,
		Label:    "listener collection",
		Severity: SeverityOK,
	}

	if state.CollectionError == "" {
		return result
	}

	result.Severity = SeverityWarn
	result.Summary = "listener collection failed"
	result.Detail = state.CollectionError
	return result
}

func dnsCoverageCheck(key, label string, probe SocketProbe) CheckResult {
	result := CheckResult{
		Key:      key,
		Label:    label,
		Severity: SeverityOK,
	}

	missing := missingFamilies(probe)
	if len(missing) == 0 {
		return result
	}

	result.Severity = SeverityCrit
	result.Summary = fmt.Sprintf("%s missing %s", label, strings.Join(missing, " and "))
	return result
}

func localhostCheck(key, label string, probe SocketProbe) CheckResult {
	result := CheckResult{
		Key:      key,
		Label:    label,
		Severity: SeverityOK,
	}

	if probe.HasLoopback() {
		return result
	}

	result.Severity = SeverityCrit
	result.Summary = fmt.Sprintf("%s not listening on localhost", label)
	return result
}

func exposureCheck(key, label string, probe SocketProbe) CheckResult {
	result := CheckResult{
		Key:      key,
		Label:    label + " exposure",
		Severity: SeverityOK,
	}

	if !probe.HasNonLoopback() {
		return result
	}

	result.Severity = SeverityWarn
	result.Summary = fmt.Sprintf("%s exposed", label)
	return result
}

func externalDNSCheck(key, family string, root, recursive DNSProbeResult) CheckResult {
	check := CheckResult{
		Key:      key,
		Label:    "external DNS " + family,
		Severity: SeverityOK,
	}

	if root.OK() && recursive.OK() {
		return check
	}

	switch {
	case root.OK() || recursive.OK():
		check.Severity = SeverityWarn
		check.Summary = fmt.Sprintf("external DNS over %s degraded", family)
	default:
		check.Severity = SeverityCrit
		check.Summary = fmt.Sprintf("external DNS over %s failing", family)
	}
	check.Detail = fmt.Sprintf("root: %s; recursive: %s", root.Summary(), recursive.Summary())
	return check
}

func dnssecValidationCheck(result DNSSECProbeResult) CheckResult {
	check := CheckResult{
		Key:      checkDNSSEC,
		Label:    "DNSSEC validation",
		Severity: SeverityOK,
	}

	positiveOK := result.Positive.OK()
	negativeOK := result.Negative.OK()
	if positiveOK && negativeOK {
		return check
	}

	switch {
	case positiveOK || negativeOK:
		check.Severity = SeverityWarn
		check.Summary = "DNSSEC validation degraded"
	default:
		check.Severity = SeverityCrit
		check.Summary = "DNSSEC validation failing"
	}
	check.Detail = fmt.Sprintf("positive: %s; negative: %s", result.Positive.Summary(), result.Negative.Summary())
	return check
}

func piholeDNSCheck(key, family string, probe DNSProbeResult) CheckResult {
	check := CheckResult{
		Key:      key,
		Label:    "Pi-hole DNS " + family,
		Severity: SeverityOK,
	}
	if probe.OK() {
		return check
	}
	check.Severity = SeverityCrit
	check.Summary = fmt.Sprintf("Pi-hole DNS over %s failing", family)
	check.Detail = probe.Summary()
	return check
}

func piholeBlockingCheck(status PiHoleStatus) CheckResult {
	check := CheckResult{
		Key:      checkPiHoleBlocking,
		Label:    "Pi-hole blocking",
		Severity: SeverityOK,
	}
	switch {
	case status.Detail != "":
		check.Severity = SeverityWarn
		check.Summary = "Pi-hole blocking status unavailable"
		check.Detail = status.Detail
	case status.Enabled():
		return check
	case status.Blocking == "":
		check.Severity = SeverityWarn
		check.Summary = "Pi-hole blocking status unavailable"
	default:
		check.Severity = SeverityCrit
		check.Summary = fmt.Sprintf("Pi-hole blocking %s", status.Blocking)
	}
	return check
}

func piholeUpstreamsCheck(upstreams PiHoleUpstreams) CheckResult {
	check := CheckResult{
		Key:      checkPiHoleUpstreams,
		Label:    "Pi-hole upstreams",
		Severity: SeverityOK,
	}
	switch {
	case upstreams.Detail != "":
		check.Severity = SeverityWarn
		check.Summary = "Pi-hole upstream configuration unavailable"
		check.Detail = upstreams.Detail
	case upstreams.MatchesExpected:
		return check
	default:
		check.Severity = SeverityCrit
		check.Summary = "Pi-hole upstreams mismatch"
		check.Detail = fmt.Sprintf("got %s", strings.Join(upstreams.Servers, ", "))
		return check
	}
	return check
}

func piholeGravityCheck(gravity PiHoleGravity) CheckResult {
	check := CheckResult{
		Key:      checkPiHoleGravity,
		Label:    "Pi-hole gravity freshness",
		Severity: SeverityOK,
	}
	switch {
	case gravity.Detail != "":
		check.Severity = SeverityWarn
		check.Summary = "Pi-hole gravity status unavailable"
		check.Detail = gravity.Detail
	case gravity.LastUpdated.IsZero():
		check.Severity = SeverityWarn
		check.Summary = "Pi-hole gravity status unavailable"
	case gravity.Stale:
		check.Severity = SeverityWarn
		check.Summary = "Pi-hole gravity stale"
		check.Detail = "last updated " + gravity.LastUpdated.Local().Format(time.RFC3339)
	}
	return check
}

func tailscaleConnectedCheck(state TailscaleState) CheckResult {
	check := CheckResult{
		Key:      checkTailscale,
		Label:    "Tailscale connectivity",
		Severity: SeverityOK,
	}

	if state.Status.Connected {
		return check
	}

	check.Severity = SeverityCrit
	switch {
	case state.Status.Detail != "" && state.Status.BackendState == "":
		check.Summary = "Tailscale state unavailable"
		check.Detail = state.Status.Detail
	case !state.Status.Running:
		check.Summary = "Tailscale not running"
	case !state.Status.Authenticated:
		check.Summary = "Tailscale not authenticated"
	case state.Addresses.IPv4 == "" && state.Addresses.IPv6 == "":
		check.Summary = "Tailscale has no assigned address"
	default:
		check.Summary = "Tailscale disconnected"
	}

	var detail []string
	if state.Status.BackendState != "" {
		detail = append(detail, "backend="+state.Status.BackendState)
	}
	if state.Status.Detail != "" {
		detail = append(detail, state.Status.Detail)
	}
	if state.Status.Tailnet != "" {
		detail = append(detail, "tailnet="+state.Status.Tailnet)
	}
	if check.Detail == "" {
		check.Detail = strings.Join(detail, "; ")
	}
	return check
}

func missingFamilies(probe SocketProbe) []string {
	var missing []string
	if !probe.HasNonLoopbackIPv4() {
		missing = append(missing, "IPv4")
	}
	if !probe.HasNonLoopbackIPv6() {
		missing = append(missing, "IPv6")
	}
	return missing
}
