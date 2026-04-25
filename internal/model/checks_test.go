package model

import (
	"testing"
	"time"
)

func TestInterfaceOperationalCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		state    SystemState
		severity Severity
		summary  string
	}{
		{
			name: "up",
			state: SystemState{
				Interface: InterfaceState{IfName: "eno1", OperState: "up"},
			},
			severity: SeverityOK,
		},
		{
			name: "down",
			state: SystemState{
				Interface: InterfaceState{IfName: "eno1", OperState: "down"},
			},
			severity: SeverityCrit,
			summary:  "interface eno1 operstate down",
		},
		{
			name: "unknown interface during startup",
			state: SystemState{
				Interface: InterfaceState{OperState: "unknown"},
			},
			severity: SeverityOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := interfaceOperationalCheck(tt.state)
			if got.Severity != tt.severity {
				t.Fatalf("Severity = %s, want %s", got.Severity, tt.severity)
			}
			if got.Summary != tt.summary {
				t.Fatalf("Summary = %q, want %q", got.Summary, tt.summary)
			}
		})
	}
}

func TestEvaluateChecksIncludesInterfaceOperationalCheck(t *testing.T) {
	t.Parallel()

	checks := EvaluateChecks("", SystemState{
		Interface: InterfaceState{IfName: "eno1", OperState: "lowerlayerdown"},
	})

	got, ok := checks[checkInterfaceOper]
	if !ok {
		t.Fatal("interface operational check missing")
	}
	if got.Severity != SeverityCrit {
		t.Fatalf("Severity = %s, want %s", got.Severity, SeverityCrit)
	}
}

func TestCollectionChecks(t *testing.T) {
	t.Parallel()

	t.Run("interface collection failure warns", func(t *testing.T) {
		t.Parallel()

		got := interfaceCollectionCheck(InterfaceState{CollectionError: "netlink unavailable"})
		if got.Severity != SeverityWarn {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityWarn)
		}
		if got.Summary != "interface collection failed" {
			t.Fatalf("Summary = %q, want %q", got.Summary, "interface collection failed")
		}
		if got.Detail != "netlink unavailable" {
			t.Fatalf("Detail = %q, want %q", got.Detail, "netlink unavailable")
		}
	})

	t.Run("listener collection failure warns", func(t *testing.T) {
		t.Parallel()

		got := listenerCollectionCheck(ListenerState{CollectionError: "open /proc/net/tcp: permission denied"})
		if got.Severity != SeverityWarn {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityWarn)
		}
		if got.Summary != "listener collection failed" {
			t.Fatalf("Summary = %q, want %q", got.Summary, "listener collection failed")
		}
		if got.Detail != "open /proc/net/tcp: permission denied" {
			t.Fatalf("Detail = %q, want %q", got.Detail, "open /proc/net/tcp: permission denied")
		}
	})
}

func TestDNSSECValidationCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		result   DNSSECProbeResult
		severity Severity
		summary  string
	}{
		{
			name: "healthy",
			result: DNSSECProbeResult{
				Positive: DNSSECProbeAttempt{Status: DNSSECProbeStatusOK},
				Negative: DNSSECProbeAttempt{Status: DNSSECProbeStatusOK},
			},
			severity: SeverityOK,
		},
		{
			name: "degraded",
			result: DNSSECProbeResult{
				Positive: DNSSECProbeAttempt{Status: DNSSECProbeStatusOK},
				Negative: DNSSECProbeAttempt{Status: DNSSECProbeStatusUnexpectedSuccess, Detail: "expected SERVFAIL"},
			},
			severity: SeverityWarn,
			summary:  "DNSSEC validation degraded",
		},
		{
			name: "failing",
			result: DNSSECProbeResult{
				Positive: DNSSECProbeAttempt{Status: DNSSECProbeStatusUnexpectedFailure, Detail: "missing AD bit"},
				Negative: DNSSECProbeAttempt{Status: DNSSECProbeStatusUnexpectedSuccess, Detail: "expected SERVFAIL"},
			},
			severity: SeverityCrit,
			summary:  "DNSSEC validation failing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := dnssecValidationCheck(tt.result)
			if got.Severity != tt.severity {
				t.Fatalf("Severity = %s, want %s", got.Severity, tt.severity)
			}
			if got.Summary != tt.summary {
				t.Fatalf("Summary = %q, want %q", got.Summary, tt.summary)
			}
		})
	}
}

func TestPiHoleChecks(t *testing.T) {
	t.Parallel()

	t.Run("dns failure is critical", func(t *testing.T) {
		t.Parallel()

		got := piholeDNSCheck(checkPiHoleDNSV4, "IPv4", DNSProbeResult{
			Status: DNSProbeStatusTimeout,
			Detail: "timeout",
		})
		if got.Severity != SeverityCrit {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityCrit)
		}
	})

	t.Run("blocking disabled is critical", func(t *testing.T) {
		t.Parallel()

		got := piholeBlockingCheck(PiHoleStatus{Blocking: "disabled"})
		if got.Severity != SeverityCrit {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityCrit)
		}
	})

	t.Run("upstream mismatch is critical", func(t *testing.T) {
		t.Parallel()

		got := piholeUpstreamsCheck(PiHoleUpstreams{
			Servers:         []string{"8.8.8.8#53"},
			MatchesExpected: false,
		})
		if got.Severity != SeverityCrit {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityCrit)
		}
	})

	t.Run("stale gravity warns", func(t *testing.T) {
		t.Parallel()

		got := piholeGravityCheck(PiHoleGravity{
			LastUpdated: time.Now().Add(-8 * 24 * time.Hour),
			Stale:       true,
		})
		if got.Severity != SeverityWarn {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityWarn)
		}
	})
}

func TestTailscaleConnectedCheck(t *testing.T) {
	t.Parallel()

	t.Run("connected is healthy", func(t *testing.T) {
		t.Parallel()

		got := tailscaleConnectedCheck(TailscaleState{
			Status: TailscaleStatus{
				Running:       true,
				Authenticated: true,
				Connected:     true,
				BackendState:  "Running",
			},
			Addresses: TailscaleAddresses{IPv4: "100.64.0.1"},
		})
		if got.Severity != SeverityOK {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityOK)
		}
	})

	t.Run("missing state is critical", func(t *testing.T) {
		t.Parallel()

		got := tailscaleConnectedCheck(TailscaleState{
			Status: TailscaleStatus{
				Detail: "exec: tailscale not found",
			},
		})
		if got.Severity != SeverityCrit {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityCrit)
		}
		if got.Summary != "Tailscale state unavailable" {
			t.Fatalf("Summary = %q, want %q", got.Summary, "Tailscale state unavailable")
		}
	})

	t.Run("not authenticated is critical", func(t *testing.T) {
		t.Parallel()

		got := tailscaleConnectedCheck(TailscaleState{
			Status: TailscaleStatus{
				Running:       true,
				Authenticated: false,
				BackendState:  "NeedsLogin",
			},
		})
		if got.Severity != SeverityCrit {
			t.Fatalf("Severity = %s, want %s", got.Severity, SeverityCrit)
		}
		if got.Summary != "Tailscale not authenticated" {
			t.Fatalf("Summary = %q, want %q", got.Summary, "Tailscale not authenticated")
		}
	})
}
