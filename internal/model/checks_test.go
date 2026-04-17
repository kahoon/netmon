package model

import "testing"

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
