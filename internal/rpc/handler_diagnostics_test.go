package rpc

import (
	"context"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/monitor"
	netmonv1 "github.com/kahoon/netmon/proto/netmon/v1"
)

func TestGetDiagnosticsMapsAlertHistory(t *testing.T) {
	at := time.Unix(1700000000, 0).Local()
	handler := &Handler{
		svc: &fakeService{
			diagnostics: monitor.Diagnostics{
				AlertHistoryInterval: 7 * 24 * time.Hour,
				Alerts: []monitor.AlertAttempt{
					{
						At:             at,
						DeliveryStatus: monitor.AlertNotDelivered,
						Severity:       model.SeverityCrit,
						Title:          "CRIT netmon eno1",
						Reason:         "pihole refresh",
						Summary:        "Pi-hole blocking disabled",
						DeliveryError:  "dial timeout",
					},
				},
			},
		},
	}

	resp, err := handler.GetDiagnostics(context.Background(), connect.NewRequest(&netmonv1.GetDiagnosticsRequest{}))
	if err != nil {
		t.Fatalf("GetDiagnostics() error = %v", err)
	}

	if got, want := resp.Msg.GetAlertHistoryInterval(), "168h0m0s"; got != want {
		t.Fatalf("AlertHistoryInterval = %q, want %q", got, want)
	}
	alerts := resp.Msg.GetAlerts()
	if got, want := len(alerts), 1; got != want {
		t.Fatalf("len(Alerts) = %d, want %d", got, want)
	}
	alert := alerts[0]
	if got, want := alert.GetDeliveryStatus(), netmonv1.AlertDeliveryStatus_ALERT_DELIVERY_STATUS_NOT_DELIVERED; got != want {
		t.Fatalf("DeliveryStatus = %s, want %s", got, want)
	}
	if got, want := alert.GetSeverity(), netmonv1.Severity_SEVERITY_CRIT; got != want {
		t.Fatalf("Severity = %s, want %s", got, want)
	}
	if got, want := alert.GetReason(), "pihole refresh"; got != want {
		t.Fatalf("Reason = %q, want %q", got, want)
	}
	if got, want := alert.GetSummary(), "Pi-hole blocking disabled"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
}
