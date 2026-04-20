package rpc

import (
	"context"
	"errors"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/monitor"
	"github.com/kahoon/netmon/internal/stats"
	"github.com/kahoon/netmon/internal/trace"
	netmonv1 "github.com/kahoon/netmon/proto/netmon/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

type fakeService struct {
	status        monitor.StatusView
	watchSub      monitor.StatusSubscription
	taskSub       monitor.TaskSubscription
	checkSub      monitor.CheckSubscription
	state         model.SystemState
	info          monitor.Info
	snapshot      stats.Snapshot
	refreshScope  monitor.RefreshScope
	refreshErr    error
	debug         bool
	statsInterval time.Duration
	statsErr      error
}

func (f *fakeService) GetStatus(context.Context) (monitor.StatusView, error) { return f.status, nil }
func (f *fakeService) WatchStatus(context.Context) (monitor.StatusSubscription, error) {
	if f.watchSub != nil {
		return f.watchSub, nil
	}
	return &fakeSubscription{updates: make(chan monitor.StatusView)}, nil
}
func (f *fakeService) WatchTasks(context.Context) (monitor.TaskSubscription, error) {
	if f.taskSub != nil {
		return f.taskSub, nil
	}
	return &fakeTaskSubscription{updates: make(chan monitor.TaskEvent)}, nil
}
func (f *fakeService) WatchChecks(context.Context) (monitor.CheckSubscription, error) {
	if f.checkSub != nil {
		return f.checkSub, nil
	}
	return &fakeCheckSubscription{updates: make(chan monitor.CheckEvent)}, nil
}
func (f *fakeService) GetState(context.Context) (model.SystemState, error) { return f.state, nil }
func (f *fakeService) GetInfo(context.Context) (monitor.Info, error)       { return f.info, nil }
func (f *fakeService) GetStats(context.Context) (stats.Snapshot, error)    { return f.snapshot, nil }
func (f *fakeService) Trace(context.Context, monitor.RefreshScope, trace.Sink) error {
	return nil
}
func (f *fakeService) Refresh(_ context.Context, scope monitor.RefreshScope) error {
	f.refreshScope = scope
	return f.refreshErr
}
func (f *fakeService) SetDebug(_ context.Context, debug bool) error {
	f.debug = debug
	return nil
}
func (f *fakeService) SetRuntimeStatsInterval(_ context.Context, interval time.Duration) error {
	f.statsInterval = interval
	return f.statsErr
}

type fakeSubscription struct {
	updates <-chan monitor.StatusView
}

func (f *fakeSubscription) Updates() <-chan monitor.StatusView { return f.updates }
func (f *fakeSubscription) Close()                             {}

type fakeTaskSubscription struct {
	updates <-chan monitor.TaskEvent
}

func (f *fakeTaskSubscription) Updates() <-chan monitor.TaskEvent { return f.updates }
func (f *fakeTaskSubscription) Close()                            {}

type fakeCheckSubscription struct {
	updates <-chan monitor.CheckEvent
}

func (f *fakeCheckSubscription) Updates() <-chan monitor.CheckEvent { return f.updates }
func (f *fakeCheckSubscription) Close()                             {}

func TestGetStatusMapsOKSeverity(t *testing.T) {
	handler := &Handler{
		svc: &fakeService{
			status: monitor.StatusView{
				OverallSeverity: model.SeverityOK,
				Summary:         "healthy",
				PublicIPv4:      "203.0.113.10",
				PublicIPv6:      "2001:db8::10",
				Checks: []model.CheckResult{
					{
						Key:      "expected-ula",
						Label:    "expected ULA",
						Severity: model.SeverityOK,
					},
				},
			},
		},
	}

	resp, err := handler.GetStatus(context.Background(), connect.NewRequest(&netmonv1.GetStatusRequest{}))
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if got, want := resp.Msg.GetOverallSeverity(), netmonv1.Severity_SEVERITY_OK; got != want {
		t.Fatalf("GetStatus().OverallSeverity = %s, want %s", got, want)
	}
	if got, want := resp.Msg.GetChecks()[0].GetSeverity(), netmonv1.Severity_SEVERITY_OK; got != want {
		t.Fatalf("GetStatus().Checks[0].Severity = %s, want %s", got, want)
	}
	if got, want := resp.Msg.GetPublicIpv6(), "2001:db8::10"; got != want {
		t.Fatalf("GetStatus().PublicIpv6 = %q, want %q", got, want)
	}
}

func TestGetInfoMapsBuildMetadata(t *testing.T) {
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	handler := &Handler{
		svc: &fakeService{
			info: monitor.Info{
				Version:              "v0.1.0",
				Commit:               "abc123",
				BuildTime:            "2026-04-14T12:00:00Z",
				StartedAt:            startedAt,
				MonitorInterface:     "eno1",
				InterfacePoll:        10 * time.Minute,
				ListenerPoll:         10 * time.Minute,
				UpstreamPoll:         5 * time.Minute,
				UnboundPoll:          5 * time.Minute,
				PiHolePoll:           5 * time.Minute,
				RuntimeStatsInterval: 24 * time.Hour,
				NtfyHost:             "ntfy.sh",
			},
		},
	}

	resp, err := handler.GetInfo(context.Background(), connect.NewRequest(&netmonv1.GetInfoRequest{}))
	if err != nil {
		t.Fatalf("GetInfo() error = %v", err)
	}

	if got, want := resp.Msg.GetCommit(), "abc123"; got != want {
		t.Fatalf("GetInfo().Commit = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetBuildTime(), "2026-04-14T12:00:00Z"; got != want {
		t.Fatalf("GetInfo().BuildTime = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetStartedAtUnix(), startedAt.Unix(); got != want {
		t.Fatalf("GetInfo().StartedAtUnix = %d, want %d", got, want)
	}
	if got, want := resp.Msg.GetUnboundPoll(), "5m0s"; got != want {
		t.Fatalf("GetInfo().UnboundPoll = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetPiholePoll(), "5m0s"; got != want {
		t.Fatalf("GetInfo().PiholePoll = %q, want %q", got, want)
	}
}

func TestGetStateMapsPiHoleAndUnboundState(t *testing.T) {
	handler := &Handler{
		svc: &fakeService{
			state: model.SystemState{
				Unbound: model.UnboundState{
					DNSSEC: model.DNSSECProbeResult{
						Positive: model.DNSSECProbeAttempt{
							Name:   "internetsociety.org.",
							Target: "127.0.0.1:5335",
							Status: model.DNSSECProbeStatusOK,
							Rcode:  "NOERROR",
							AD:     true,
						},
						Negative: model.DNSSECProbeAttempt{
							Name:   "dnssec-failed.org.",
							Target: "127.0.0.1:5335",
							Status: model.DNSSECProbeStatusOK,
							Rcode:  "SERVFAIL",
						},
					},
				},
				PiHole: model.PiHoleState{
					DNSV4: model.DNSProbeResult{
						Name:   "e.root-servers.net. via Pi-hole",
						Target: "127.0.0.1:53",
						Status: model.DNSProbeStatusOK,
					},
					Status: model.PiHoleStatus{
						Blocking:    "enabled",
						CoreVersion: "6.0",
					},
					Upstreams: model.PiHoleUpstreams{
						Servers:         []string{"127.0.0.1#5335", "::1#5335"},
						MatchesExpected: true,
					},
					Gravity: model.PiHoleGravity{
						Stale: false,
					},
					Counters: model.PiHoleCounters{
						QueriesTotal: 42,
					},
					LatencyIPv4: model.DNSLatencyWindow{
						Samples: 3,
						Trend:   model.LatencyTrendStable,
					},
				},
			},
		},
	}

	resp, err := handler.GetState(context.Background(), connect.NewRequest(&netmonv1.GetStateRequest{}))
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}

	if got, want := resp.Msg.GetUnbound().GetDnssec().GetPositive().GetName(), "internetsociety.org."; got != want {
		t.Fatalf("GetState().Unbound.Dnssec.Positive.Name = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetUnbound().GetDnssec().GetPositive().GetAd(), true; got != want {
		t.Fatalf("GetState().Unbound.Dnssec.Positive.Ad = %t, want %t", got, want)
	}
	if got, want := resp.Msg.GetUnbound().GetDnssec().GetNegative().GetRcode(), "SERVFAIL"; got != want {
		t.Fatalf("GetState().Unbound.Dnssec.Negative.Rcode = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetPihole().GetStatus().GetBlocking(), "enabled"; got != want {
		t.Fatalf("GetState().Pihole.Status.Blocking = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetPihole().GetUpstreams().GetServers()[0], "127.0.0.1#5335"; got != want {
		t.Fatalf("GetState().Pihole.Upstreams.Servers[0] = %q, want %q", got, want)
	}
	if got, want := resp.Msg.GetPihole().GetCounters().GetQueriesTotal(), uint64(42); got != want {
		t.Fatalf("GetState().Pihole.Counters.QueriesTotal = %d, want %d", got, want)
	}
	if got, want := resp.Msg.GetPihole().GetLatencyIpv4().GetTrend(), "stable"; got != want {
		t.Fatalf("GetState().Pihole.LatencyIpv4.Trend = %q, want %q", got, want)
	}
}

func TestRefreshRejectsUnknownScope(t *testing.T) {
	handler := &Handler{svc: &fakeService{}}

	_, err := handler.Refresh(context.Background(), connect.NewRequest(&netmonv1.RefreshRequest{
		Scope: netmonv1.RefreshScope(99),
	}))
	if err == nil {
		t.Fatal("Refresh() error = nil, want invalid argument error")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("Refresh() error = %T, want *connect.Error", err)
	}
	if got, want := connectErr.Code(), connect.CodeInvalidArgument; got != want {
		t.Fatalf("Refresh() code = %s, want %s", got, want)
	}
}

func TestMapCheckEvent(t *testing.T) {
	event := monitor.CheckEvent{
		At:               time.Unix(1_700_000_000, 0).Local(),
		Key:              "interface-oper",
		Label:            "interface operational",
		PreviousSeverity: model.SeverityOK,
		CurrentSeverity:  model.SeverityCrit,
		CurrentSummary:   "interface eno1 operstate down",
	}
	got := mapCheckEvent(event)
	if got.GetKey() != "interface-oper" {
		t.Fatalf("Event.Key = %q, want %q", got.GetKey(), "interface-oper")
	}
	if got.GetPreviousSeverity() != netmonv1.Severity_SEVERITY_OK {
		t.Fatalf("Event.PreviousSeverity = %s, want %s", got.GetPreviousSeverity(), netmonv1.Severity_SEVERITY_OK)
	}
	if got.GetCurrentSeverity() != netmonv1.Severity_SEVERITY_CRIT {
		t.Fatalf("Event.CurrentSeverity = %s, want %s", got.GetCurrentSeverity(), netmonv1.Severity_SEVERITY_CRIT)
	}
}

func TestSetRuntimeStatsIntervalMapsTypedDuration(t *testing.T) {
	service := &fakeService{}
	handler := &Handler{svc: service}

	resp, err := handler.SetRuntimeStatsInterval(context.Background(), connect.NewRequest(&netmonv1.SetRuntimeStatsIntervalRequest{
		Interval: durationpb.New(30 * time.Minute),
	}))
	if err != nil {
		t.Fatalf("SetRuntimeStatsInterval() error = %v", err)
	}

	if got, want := service.statsInterval, 30*time.Minute; got != want {
		t.Fatalf("service interval = %s, want %s", got, want)
	}
	if got, want := resp.Msg.GetInterval().AsDuration(), 30*time.Minute; got != want {
		t.Fatalf("response interval = %s, want %s", got, want)
	}
}
