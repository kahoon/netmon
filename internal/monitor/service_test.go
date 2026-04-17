package monitor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGetStatusReturnsOrderedChecks(t *testing.T) {
	daemon := NewMonitor(config.Config{})
	daemon.state = model.SystemState{
		Upstream: model.UpstreamState{
			PublicIPv4: model.PublicIPResult{IPv4: "203.0.113.10"},
		},
	}
	daemon.checks = model.CheckSet{
		"z-extra": {
			Key:      "z-extra",
			Label:    "extra",
			Severity: model.SeverityWarn,
			Summary:  "extra issue",
		},
		"expected-ula": {
			Key:      "expected-ula",
			Label:    "expected ULA",
			Severity: model.SeverityCrit,
			Summary:  "expected ULA missing",
		},
		"usable-gua": {
			Key:      "usable-gua",
			Label:    "usable global IPv6",
			Severity: model.SeverityWarn,
			Summary:  "no usable global IPv6",
		},
	}

	status, err := daemon.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if got, want := status.PublicIPv4, "203.0.113.10"; got != want {
		t.Fatalf("GetStatus().PublicIPv4 = %q, want %q", got, want)
	}

	if got, want := status.OverallSeverity, model.SeverityCrit; got != want {
		t.Fatalf("GetStatus().OverallSeverity = %s, want %s", got, want)
	}

	if len(status.Checks) != 3 {
		t.Fatalf("len(GetStatus().Checks) = %d, want 3", len(status.Checks))
	}

	if got, want := status.Checks[0].Key, "expected-ula"; got != want {
		t.Fatalf("GetStatus().Checks[0].Key = %q, want %q", got, want)
	}
	if got, want := status.Checks[1].Key, "usable-gua"; got != want {
		t.Fatalf("GetStatus().Checks[1].Key = %q, want %q", got, want)
	}
	if got, want := status.Checks[2].Key, "z-extra"; got != want {
		t.Fatalf("GetStatus().Checks[2].Key = %q, want %q", got, want)
	}
}

func TestGetStateReturnsCopy(t *testing.T) {
	daemon := NewMonitor(config.Config{})
	daemon.state = model.SystemState{
		Interface: model.InterfaceState{
			ULA: []string{"fd00::1"},
		},
	}

	state, err := daemon.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}

	state.Interface.ULA[0] = "fd00::2"

	if got, want := daemon.state.Interface.ULA[0], "fd00::1"; got != want {
		t.Fatalf("monitor state mutated through GetState() copy: got %q want %q", got, want)
	}
}

func TestGetInfoIncludesBuildAndRuntimeMetadata(t *testing.T) {
	cfg := config.Config{
		MonitorInterface:      "eno1",
		InterfacePollInterval: 10 * time.Minute,
		ListenerPollInterval:  10 * time.Minute,
		UpstreamPollInterval:  5 * time.Minute,
		RuntimeStatsInterval:  24 * time.Hour,
		NtfyHost:              "ntfy.sh",
	}
	daemon := NewMonitor(cfg)

	info, err := daemon.GetInfo(context.Background())
	if err != nil {
		t.Fatalf("GetInfo() error = %v", err)
	}

	if got, want := info.MonitorInterface, "eno1"; got != want {
		t.Fatalf("GetInfo().MonitorInterface = %q, want %q", got, want)
	}
	if info.StartedAt.IsZero() {
		t.Fatal("GetInfo().StartedAt is zero")
	}
	if got, want := info.NtfyHost, "ntfy.sh"; got != want {
		t.Fatalf("GetInfo().NtfyHost = %q, want %q", got, want)
	}
}

func TestSetRuntimeStatsIntervalUpdatesInfo(t *testing.T) {
	daemon := NewMonitor(config.Config{RuntimeStatsInterval: 24 * time.Hour})

	if err := daemon.SetRuntimeStatsInterval(context.Background(), 30*time.Minute); err != nil {
		t.Fatalf("SetRuntimeStatsInterval() error = %v", err)
	}

	info, err := daemon.GetInfo(context.Background())
	if err != nil {
		t.Fatalf("GetInfo() error = %v", err)
	}

	if got, want := info.RuntimeStatsInterval, 30*time.Minute; got != want {
		t.Fatalf("GetInfo().RuntimeStatsInterval = %s, want %s", got, want)
	}
}

func TestWatchStatusReturnsInitialSnapshotAndUpdates(t *testing.T) {
	daemon := NewMonitor(config.Config{ExpectedULA: "fd00::/64"})
	daemon.notifier = &NtfyNotifier{
		host:  "ntfy.sh",
		topic: "test",
		client: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			}),
		},
	}
	daemon.state = model.SystemState{
		Upstream: model.UpstreamState{
			PublicIPv4: model.PublicIPResult{IPv4: "203.0.113.10"},
		},
	}
	daemon.checks = model.CheckSet{
		"expected-ula": {
			Key:      "expected-ula",
			Label:    "expected ULA",
			Severity: model.SeverityOK,
			Summary:  "expected ULA present",
		},
	}

	sub, err := daemon.WatchStatus(context.Background())
	if err != nil {
		t.Fatalf("WatchStatus() error = %v", err)
	}
	defer sub.Close()

	select {
	case initial := <-sub.Updates():
		if got, want := initial.PublicIPv4, "203.0.113.10"; got != want {
			t.Fatalf("initial PublicIPv4 = %q, want %q", got, want)
		}
		if got, want := initial.OverallSeverity, model.SeverityOK; got != want {
			t.Fatalf("initial OverallSeverity = %s, want %s", got, want)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for initial status update")
	}

	daemon.applyUpdate(context.Background(), "test update", func(current *model.SystemState) {
		current.Upstream.PublicIPv4 = model.PublicIPResult{IPv4: "203.0.113.27"}
	})

	select {
	case updated := <-sub.Updates():
		if got, want := updated.PublicIPv4, "203.0.113.27"; got != want {
			t.Fatalf("updated PublicIPv4 = %q, want %q", got, want)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for changed status update")
	}
}

func TestWatchTasksReceivesTelemetryEvents(t *testing.T) {
	daemon := NewMonitor(config.Config{})

	sub, err := daemon.WatchTasks(context.Background())
	if err != nil {
		t.Fatalf("WatchTasks() error = %v", err)
	}
	defer sub.Close()

	telemetry := newPendingTelemetry(daemon)
	telemetry.OnScheduled("refresh:upstream", 2*time.Second)

	select {
	case event := <-sub.Updates():
		if got, want := event.ID, "refresh:upstream"; got != want {
			t.Fatalf("event ID = %q, want %q", got, want)
		}
		if got, want := event.Kind, TaskEventScheduled; got != want {
			t.Fatalf("event Kind = %q, want %q", got, want)
		}
		if got, want := event.Delay, 2*time.Second; got != want {
			t.Fatalf("event Delay = %s, want %s", got, want)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for task event")
	}
}

func TestWatchTasksSeedsRecentHistory(t *testing.T) {
	daemon := NewMonitor(config.Config{})
	telemetry := newPendingTelemetry(daemon)
	for range 20 {
		telemetry.OnScheduled("refresh:listeners", 3*time.Second)
	}

	sub, err := daemon.WatchTasks(context.Background())
	if err != nil {
		t.Fatalf("WatchTasks() error = %v", err)
	}
	defer sub.Close()

	for i := range 20 {
		select {
		case event := <-sub.Updates():
			if got, want := event.ID, "refresh:listeners"; got != want {
				t.Fatalf("history event ID = %q, want %q", got, want)
			}
			if got, want := event.Kind, TaskEventScheduled; got != want {
				t.Fatalf("history event Kind = %q, want %q", got, want)
			}
			if got, want := event.Delay, 3*time.Second; got != want {
				t.Fatalf("history event Delay = %s, want %s", got, want)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for seeded history event %d", i)
		}
	}
}
