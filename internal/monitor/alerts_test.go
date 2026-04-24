package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/model"
)

func TestAlertHistoryRecordsAndPrunesAttempts(t *testing.T) {
	daemon := NewMonitor(config.Config{AlertHistoryInterval: 7 * 24 * time.Hour})
	now := time.Now().Local()

	daemon.recordAlertAttempt(Notification{
		Severity: model.SeverityWarn,
		Title:    "WARN netmon eno1",
		Reason:   "old refresh",
		Summary:  "old alert",
	}, true, nil, now.Add(-8*24*time.Hour))
	daemon.recordAlertAttempt(Notification{
		Severity: model.SeverityCrit,
		Title:    "CRIT netmon eno1",
		Reason:   "pihole refresh",
		Summary:  "Pi-hole blocking disabled",
	}, false, errors.New("dial timeout"), now)

	diagnostics, err := daemon.GetDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("GetDiagnostics() error = %v", err)
	}

	if got, want := diagnostics.AlertHistoryInterval, 7*24*time.Hour; got != want {
		t.Fatalf("AlertHistoryInterval = %s, want %s", got, want)
	}
	if got, want := len(diagnostics.Alerts), 1; got != want {
		t.Fatalf("len(Alerts) = %d, want %d", got, want)
	}
	alert := diagnostics.Alerts[0]
	if got, want := alert.DeliveryStatus, AlertNotDelivered; got != want {
		t.Fatalf("DeliveryStatus = %s, want %s", got, want)
	}
	if got, want := alert.Summary, "Pi-hole blocking disabled"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
	if got, want := alert.DeliveryError, "dial timeout"; got != want {
		t.Fatalf("DeliveryError = %q, want %q", got, want)
	}
}

func TestSetAlertHistoryIntervalDisablesHistory(t *testing.T) {
	daemon := NewMonitor(config.Config{AlertHistoryInterval: 7 * 24 * time.Hour})

	daemon.recordAlertAttempt(Notification{
		Severity: model.SeverityWarn,
		Title:    "WARN netmon eno1",
		Reason:   "pihole refresh",
		Summary:  "Pi-hole blocking disabled",
	}, true, nil, time.Now().Local())

	if err := daemon.SetAlertHistoryInterval(context.Background(), 0); err != nil {
		t.Fatalf("SetAlertHistoryInterval() error = %v", err)
	}

	diagnostics, err := daemon.GetDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("GetDiagnostics() error = %v", err)
	}
	if got := len(diagnostics.Alerts); got != 0 {
		t.Fatalf("len(Alerts) = %d, want 0", got)
	}
}

func TestAlertHistoryTruncatesFields(t *testing.T) {
	daemon := NewMonitor(config.Config{AlertHistoryInterval: 7 * 24 * time.Hour})
	longValue := strings.Repeat("x", alertFieldLimit+10)

	daemon.recordAlertAttempt(Notification{
		Severity: model.SeverityWarn,
		Title:    longValue,
		Reason:   longValue,
		Summary:  longValue,
	}, false, errors.New(longValue), time.Now().Local())

	diagnostics, err := daemon.GetDiagnostics(context.Background())
	if err != nil {
		t.Fatalf("GetDiagnostics() error = %v", err)
	}
	alert := diagnostics.Alerts[0]
	for name, value := range map[string]string{
		"Title":         alert.Title,
		"Reason":        alert.Reason,
		"Summary":       alert.Summary,
		"DeliveryError": alert.DeliveryError,
	} {
		if got, want := len([]rune(value)), alertFieldLimit; got != want {
			t.Fatalf("%s length = %d, want %d", name, got, want)
		}
	}
}
