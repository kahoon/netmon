package monitor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/events"
	"github.com/kahoon/netmon/internal/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type staticCollector[T any] struct {
	value T
	err   error
}

func (c staticCollector[T]) Collect(context.Context) (T, error) {
	return c.value, c.err
}

func TestGetStatusReturnsOrderedChecks(t *testing.T) {
	daemon := NewMonitor(config.Config{})
	daemon.state = model.SystemState{
		Upstream: model.UpstreamState{
			PublicIPv4: model.PublicIPObservation{IP: "203.0.113.10"},
			PublicIPv6: model.PublicIPObservation{IP: "2001:db8::10"},
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
	if got, want := status.PublicIPv6, "2001:db8::10"; got != want {
		t.Fatalf("GetStatus().PublicIPv6 = %q, want %q", got, want)
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
			ULA:             []string{"fd00::1"},
			CollectionError: "netlink failed",
		},
		Listeners: model.ListenerState{
			CollectionError: "listener failed",
		},
		Unbound: model.UnboundState{
			DNSSEC: model.DNSSECProbeResult{
				Positive: model.DNSSECProbeAttempt{
					Name:   "internetsociety.org.",
					Status: model.DNSSECProbeStatusOK,
				},
			},
		},
		PiHole: model.PiHoleState{
			Upstreams: model.PiHoleUpstreams{
				Servers: []string{"127.0.0.1#5335"},
			},
		},
		Tailscale: model.TailscaleState{
			Roles: model.TailscaleRoles{
				AdvertisedRoutes: []string{"192.168.1.0/24"},
			},
		},
	}

	state, err := daemon.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}

	state.Interface.ULA[0] = "fd00::2"
	state.Interface.CollectionError = "changed"
	state.Listeners.CollectionError = "changed"
	state.Unbound.DNSSEC.Positive.Name = "changed"
	state.PiHole.Upstreams.Servers[0] = "8.8.8.8#53"
	state.Tailscale.Roles.AdvertisedRoutes[0] = "10.0.0.0/24"

	if got, want := daemon.state.Interface.ULA[0], "fd00::1"; got != want {
		t.Fatalf("monitor state mutated through GetState() copy: got %q want %q", got, want)
	}
	if got, want := daemon.state.Interface.CollectionError, "netlink failed"; got != want {
		t.Fatalf("monitor interface collection error mutated through GetState() copy: got %q want %q", got, want)
	}
	if got, want := daemon.state.Listeners.CollectionError, "listener failed"; got != want {
		t.Fatalf("monitor listener collection error mutated through GetState() copy: got %q want %q", got, want)
	}
	if got, want := daemon.state.Unbound.DNSSEC.Positive.Name, "internetsociety.org."; got != want {
		t.Fatalf("monitor unbound state mutated through GetState() copy: got %q want %q", got, want)
	}
	if got, want := daemon.state.PiHole.Upstreams.Servers[0], "127.0.0.1#5335"; got != want {
		t.Fatalf("monitor pihole state mutated through GetState() copy: got %q want %q", got, want)
	}
	if got, want := daemon.state.Tailscale.Roles.AdvertisedRoutes[0], "192.168.1.0/24"; got != want {
		t.Fatalf("monitor tailscale state mutated through GetState() copy: got %q want %q", got, want)
	}
}

func TestInitializeSendsStartupCollectionFailureNotification(t *testing.T) {
	authErr := errors.New("Pi-hole authentication failed")
	cfg := config.Config{
		MonitorInterface:     "eno1",
		NtfyHost:             "ntfy.example",
		Topic:                "alerts",
		AlertHistoryInterval: 7 * 24 * time.Hour,
	}
	daemon := NewMonitor(cfg)
	daemon.interfaceCollector = staticCollector[model.InterfaceState]{
		value: model.InterfaceState{IfName: "eno1", OperState: "up"},
	}
	daemon.listenerCollector = staticCollector[model.ListenerState]{}
	daemon.upstreamCollector = staticCollector[model.UpstreamState]{}
	daemon.unboundCollector = staticCollector[model.UnboundState]{}
	daemon.piholeCollector = staticCollector[model.PiHoleState]{
		value: model.PiHoleState{
			CollectionError: authErr.Error(),
			CollectionFailure: model.NewCollectionFailure(
				model.CollectionFailureAuthentication,
				"Pi-hole API authentication failed",
				authErr,
			),
		},
		err: authErr,
	}
	daemon.tailscaleCollector = staticCollector[model.TailscaleState]{
		value: model.TailscaleState{
			Status: model.TailscaleStatus{
				Running:       true,
				Authenticated: true,
				Connected:     true,
			},
			Addresses: model.TailscaleAddresses{IPv4: "100.64.0.1"},
		},
	}

	var postedBody string
	var postedTitle string
	daemon.notifier = &NtfyNotifier{
		host:  cfg.NtfyHost,
		topic: cfg.Topic,
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("ReadAll(notification body) error = %v", err)
				}
				postedBody = string(body)
				postedTitle = req.Header.Get("Title")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			}),
		},
	}

	if err := daemon.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if got, want := postedTitle, "WARN netmon eno1"; got != want {
		t.Fatalf("posted title = %q, want %q", got, want)
	}
	if !strings.Contains(postedBody, "reason: startup collection") {
		t.Fatalf("posted body = %q, want startup collection reason", postedBody)
	}
	if !strings.Contains(postedBody, "- Pi-hole API authentication failed") {
		t.Fatalf("posted body = %q, want Pi-hole authentication summary", postedBody)
	}

	diagnostics := daemon.alerts.Snapshot(time.Now().Local())
	if len(diagnostics.Alerts) != 1 {
		t.Fatalf("len(alert history) = %d, want 1", len(diagnostics.Alerts))
	}
	if got, want := diagnostics.Alerts[0].Summary, "Pi-hole API authentication failed"; got != want {
		t.Fatalf("alert summary = %q, want %q", got, want)
	}
	if got, want := diagnostics.Alerts[0].DeliveryStatus, AlertDelivered; got != want {
		t.Fatalf("alert delivery status = %q, want %q", got, want)
	}
}

func TestInitializeKeepsInterfaceCollectionFailureInState(t *testing.T) {
	cfg := config.Config{
		MonitorInterface:     "eno1",
		NtfyHost:             "ntfy.example",
		Topic:                "alerts",
		AlertHistoryInterval: 7 * 24 * time.Hour,
	}
	daemon := NewMonitor(cfg)
	daemon.interfaceCollector = staticCollector[model.InterfaceState]{
		err: errors.New("link not found"),
	}
	daemon.listenerCollector = staticCollector[model.ListenerState]{}
	daemon.upstreamCollector = staticCollector[model.UpstreamState]{}
	daemon.unboundCollector = staticCollector[model.UnboundState]{}
	daemon.piholeCollector = staticCollector[model.PiHoleState]{}
	daemon.tailscaleCollector = staticCollector[model.TailscaleState]{}
	daemon.notifier = &NtfyNotifier{
		host:  cfg.NtfyHost,
		topic: cfg.Topic,
		client: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			}),
		},
	}

	if err := daemon.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	state, err := daemon.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}
	if got, want := state.Interface.IfName, "eno1"; got != want {
		t.Fatalf("Interface.IfName = %q, want %q", got, want)
	}
	if got, want := state.Interface.CollectionError, "link not found"; got != want {
		t.Fatalf("Interface.CollectionError = %q, want %q", got, want)
	}
}

func TestGetInfoIncludesBuildAndRuntimeMetadata(t *testing.T) {
	cfg := config.Config{
		MonitorInterface:      "eno1",
		InterfacePollInterval: 10 * time.Minute,
		ListenerPollInterval:  10 * time.Minute,
		UpstreamPollInterval:  5 * time.Minute,
		UnboundPollInterval:   5 * time.Minute,
		PiHolePollInterval:    5 * time.Minute,
		TailscalePollInterval: 5 * time.Minute,
		RuntimeStatsInterval:  24 * time.Hour,
		AlertHistoryInterval:  7 * 24 * time.Hour,
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
	if got, want := info.UnboundPoll, 5*time.Minute; got != want {
		t.Fatalf("GetInfo().UnboundPoll = %s, want %s", got, want)
	}
	if got, want := info.PiHolePoll, 5*time.Minute; got != want {
		t.Fatalf("GetInfo().PiHolePoll = %s, want %s", got, want)
	}
	if got, want := info.TailscalePoll, 5*time.Minute; got != want {
		t.Fatalf("GetInfo().TailscalePoll = %s, want %s", got, want)
	}
	if got, want := info.AlertHistoryInterval, 7*24*time.Hour; got != want {
		t.Fatalf("GetInfo().AlertHistoryInterval = %s, want %s", got, want)
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
			PublicIPv4: model.PublicIPObservation{IP: "203.0.113.10"},
			PublicIPv6: model.PublicIPObservation{IP: "2001:db8::10"},
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
		if got, want := initial.PublicIPv6, "2001:db8::10"; got != want {
			t.Fatalf("initial PublicIPv6 = %q, want %q", got, want)
		}
		if got, want := initial.OverallSeverity, model.SeverityOK; got != want {
			t.Fatalf("initial OverallSeverity = %s, want %s", got, want)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for initial status update")
	}

	daemon.applyUpdate(context.Background(), "test update", func(current *model.SystemState) {
		current.Upstream.PublicIPv4 = model.PublicIPObservation{IP: "203.0.113.27"}
		current.Upstream.PublicIPv6 = model.PublicIPObservation{IP: "2001:db8::27"}
	})

	select {
	case updated := <-sub.Updates():
		if got, want := updated.PublicIPv4, "203.0.113.27"; got != want {
			t.Fatalf("updated PublicIPv4 = %q, want %q", got, want)
		}
		if got, want := updated.PublicIPv6, "2001:db8::27"; got != want {
			t.Fatalf("updated PublicIPv6 = %q, want %q", got, want)
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
	for range 100 {
		daemon.bus.Emit(events.StatusChanged{
			At: time.Now().Local(),
			Status: events.StatusView{
				Summary: "healthy",
			},
		})
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

func TestWatchChecksSeedsRecentHistory(t *testing.T) {
	daemon := NewMonitor(config.Config{})
	daemon.state = model.SystemState{}
	daemon.checks = model.EvaluateChecks("", daemon.state)

	daemon.applyUpdate(context.Background(), "test change", func(current *model.SystemState) {
		current.Interface = model.InterfaceState{IfName: "eno1", OperState: "down"}
	})

	sub, err := daemon.WatchChecks(context.Background())
	if err != nil {
		t.Fatalf("WatchChecks() error = %v", err)
	}
	defer sub.Close()

	select {
	case event := <-sub.Updates():
		if got, want := event.Key, "interface-oper"; got != want {
			t.Fatalf("event Key = %q, want %q", got, want)
		}
		if got, want := event.PreviousSeverity, model.SeverityOK; got != want {
			t.Fatalf("event PreviousSeverity = %s, want %s", got, want)
		}
		if got, want := event.CurrentSeverity, model.SeverityCrit; got != want {
			t.Fatalf("event CurrentSeverity = %s, want %s", got, want)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for check event")
	}
}
