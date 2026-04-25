package monitor

import (
	"strings"
	"testing"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/model"
)

func TestBuildChangeNotificationCompactBody(t *testing.T) {
	t.Parallel()

	cfg := config.Config{MonitorInterface: "eno1"}
	previousState := model.SystemState{
		Upstream: model.UpstreamState{
			PublicIPv4: model.PublicIPObservation{IP: "198.51.100.10"},
		},
	}
	currentState := model.SystemState{
		Upstream: model.UpstreamState{
			PublicIPv4: model.PublicIPObservation{IP: "198.51.100.20"},
		},
	}

	previousChecks := makeCheckSet(
		model.CheckResult{Key: "interface-oper", Label: "interface operational", Severity: model.SeverityCrit, Summary: "interface eno1 operstate down"},
		model.CheckResult{Key: "expected-ula", Label: "expected ULA", Severity: model.SeverityCrit, Summary: "expected ULA missing"},
		model.CheckResult{Key: "external-dns-v4", Label: "external DNS IPv4", Severity: model.SeverityWarn, Summary: "external DNS over IPv4 failing"},
	)
	currentChecks := makeCheckSet(
		model.CheckResult{Key: "external-dns-v4", Label: "external DNS IPv4", Severity: model.SeverityOK},
		model.CheckResult{Key: "dns53-tcp", Label: "53/tcp", Severity: model.SeverityCrit, Summary: "53/tcp missing IPv6"},
	)

	note := BuildChangeNotification(cfg, "upstream poll", previousState, currentState, previousChecks, currentChecks)
	if note == nil {
		t.Fatal("BuildChangeNotification() = nil, want notification")
	}
	if note.Severity != model.SeverityCrit {
		t.Fatalf("Severity = %s, want %s", note.Severity, model.SeverityCrit)
	}

	lines := strings.Split(note.Body, "\n")
	if len(lines) < 6 {
		t.Fatalf("notification body too short: %q", note.Body)
	}
	if got, want := lines[0], "reason: upstream poll"; got != want {
		t.Fatalf("line 1 = %q, want %q", got, want)
	}
	if got, want := lines[1], "severity: CRIT"; got != want {
		t.Fatalf("line 2 = %q, want %q", got, want)
	}

	wantLines := []string{
		"- interface operational recovered",
		"- expected ULA recovered",
		"- 53/tcp missing IPv6",
		"- external DNS IPv4 recovered",
		"- public IPv4 changed 198.51.100.10 -> 198.51.100.20",
	}
	for _, want := range wantLines {
		if !strings.Contains(note.Body, want) {
			t.Fatalf("notification body = %q, want line %q", note.Body, want)
		}
	}
	if strings.Contains(note.Body, "usable global IPv6") {
		t.Fatalf("notification body should omit unchanged OK checks: %q", note.Body)
	}
}

func TestCurrentOverallSeverityPromotesDualExternalFailure(t *testing.T) {
	t.Parallel()

	checks := makeCheckSet(
		model.CheckResult{Key: "external-dns-v4", Label: "external DNS IPv4", Severity: model.SeverityWarn},
		model.CheckResult{Key: "external-dns-v6", Label: "external DNS IPv6", Severity: model.SeverityWarn},
	)

	if got, want := model.CurrentOverallSeverity(checks), model.SeverityCrit; got != want {
		t.Fatalf("CurrentOverallSeverity() = %s, want %s", got, want)
	}
}

func TestBuildCollectionFailureNotification(t *testing.T) {
	t.Parallel()

	cfg := config.Config{MonitorInterface: "eno1"}
	checks := makeCheckSet(
		model.CheckResult{
			Key:      "pihole-collection",
			Label:    "Pi-hole collection",
			Severity: model.SeverityWarn,
			Summary:  "Pi-hole API authentication failed",
			Detail:   "Pi-hole API returned HTTP 401: unauthorized",
		},
	)

	note := BuildCollectionFailureNotification(cfg, "startup collection", checks)
	if note == nil {
		t.Fatal("BuildCollectionFailureNotification() = nil, want notification")
	}
	if got, want := note.Severity, model.SeverityWarn; got != want {
		t.Fatalf("Severity = %s, want %s", got, want)
	}
	if got, want := note.Summary, "Pi-hole API authentication failed"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
	if !strings.Contains(note.Body, "reason: startup collection") {
		t.Fatalf("Body = %q, want startup collection reason", note.Body)
	}
	if !strings.Contains(note.Body, "- Pi-hole API authentication failed") {
		t.Fatalf("Body = %q, want collection failure summary", note.Body)
	}
}

func makeCheckSet(results ...model.CheckResult) model.CheckSet {
	checks := make(model.CheckSet, len(model.CheckOrder()))
	for _, key := range model.CheckOrder() {
		checks[key] = model.CheckResult{Key: key, Label: defaultCheckLabel(key), Severity: model.SeverityOK}
	}
	for _, result := range results {
		checks[result.Key] = result
	}
	return checks
}

func defaultCheckLabel(key string) string {
	switch key {
	case "interface-collection":
		return "interface collection"
	case "expected-ula":
		return "expected ULA"
	case "interface-oper":
		return "interface operational"
	case "usable-gua":
		return "usable global IPv6"
	case "listener-collection":
		return "listener collection"
	case "dns53-tcp":
		return "53/tcp"
	case "dns53-udp":
		return "53/udp"
	case "resolver5335-tcp":
		return "5335/tcp"
	case "resolver5335-udp":
		return "5335/udp"
	case "resolver5335-exposed-tcp":
		return "5335/tcp exposure"
	case "resolver5335-exposed-udp":
		return "5335/udp exposure"
	case "external-dns-v4":
		return "external DNS IPv4"
	case "external-dns-v6":
		return "external DNS IPv6"
	case "dnssec-validation":
		return "DNSSEC validation"
	case "pihole-collection":
		return "Pi-hole collection"
	case "pihole-dns-v4":
		return "Pi-hole DNS IPv4"
	case "pihole-dns-v6":
		return "Pi-hole DNS IPv6"
	case "pihole-blocking":
		return "Pi-hole blocking"
	case "pihole-upstreams":
		return "Pi-hole upstreams"
	case "pihole-gravity":
		return "Pi-hole gravity freshness"
	case "tailscale-collection":
		return "Tailscale collection"
	case "tailscale-connected":
		return "Tailscale connectivity"
	default:
		return key
	}
}
