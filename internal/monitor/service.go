package monitor

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/kahoon/netmon/internal/events"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/stats"
	"github.com/kahoon/netmon/internal/trace"
	"github.com/kahoon/netmon/internal/version"
)

type Service interface {
	GetStatus(ctx context.Context) (StatusView, error)
	WatchStatus(ctx context.Context) (Subscription[StatusView], error)
	WatchTasks(ctx context.Context) (Subscription[TaskEvent], error)
	WatchChecks(ctx context.Context) (Subscription[CheckEvent], error)
	GetState(ctx context.Context) (SystemState, error)
	GetInfo(ctx context.Context) (Info, error)
	GetStats(ctx context.Context) (StatsSnapshot, error)
	Refresh(ctx context.Context, scope RefreshScope) error
	Trace(ctx context.Context, scope RefreshScope, sink trace.Sink) error
	SetDebug(ctx context.Context, debug bool) error
	SetRuntimeStatsInterval(ctx context.Context, interval time.Duration) error
}

func (m *Monitor) GetStatus(_ context.Context) (StatusView, error) {
	m.mu.Lock()
	state := model.CopySystemState(m.state)
	checks := model.CopyCheckSet(m.checks)
	m.mu.Unlock()

	return statusViewFromSnapshot(state, checks), nil
}

func (m *Monitor) WatchStatus(_ context.Context) (Subscription[StatusView], error) {
	return m.subscribeStatus(), nil
}

func (m *Monitor) WatchTasks(_ context.Context) (Subscription[TaskEvent], error) {
	return m.subscribeTasks(), nil
}

func (m *Monitor) WatchChecks(_ context.Context) (Subscription[CheckEvent], error) {
	return m.subscribeChecks(), nil
}

func (m *Monitor) GetState(_ context.Context) (model.SystemState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return model.CopySystemState(m.state), nil
}

func (m *Monitor) GetInfo(_ context.Context) (Info, error) {
	m.mu.Lock()
	runtimeStatsInterval := m.runtimeStatsInterval
	m.mu.Unlock()

	return Info{
		Version:              version.Version,
		Commit:               version.Commit,
		BuildTime:            version.BuildTime,
		StartedAt:            m.startedAt,
		MonitorInterface:     m.cfg.MonitorInterface,
		InterfacePoll:        m.cfg.InterfacePollInterval,
		ListenerPoll:         m.cfg.ListenerPollInterval,
		UpstreamPoll:         m.cfg.UpstreamPollInterval,
		UnboundPoll:          m.cfg.UnboundPollInterval,
		PiHolePoll:           m.cfg.PiHolePollInterval,
		TailscalePoll:        m.cfg.TailscalePollInterval,
		RuntimeStatsInterval: runtimeStatsInterval,
		NtfyHost:             m.cfg.NtfyHost,
	}, nil
}

func (m *Monitor) GetStats(_ context.Context) (stats.Snapshot, error) {
	return m.stats.Snapshot(), nil
}

func (m *Monitor) Refresh(ctx context.Context, scope RefreshScope) error {
	return m.refreshWithReason(ctx, scope, "manual refresh")
}

func (m *Monitor) Trace(ctx context.Context, refreshScope RefreshScope, sink trace.Sink) error {
	traceID := trace.NewTraceID()
	ctx = events.WithSink(events.WithHub(ctx, m.bus), trace.NewFormatterSink(traceID, sink))
	started := time.Now()
	scope := formatRefreshScope(refreshScope)
	events.Emit(ctx, events.TraceStarted{
		At:      started.Local(),
		TraceID: traceID,
		Scope:   scope,
	})
	events.Emit(ctx, events.RefreshRequested{
		At:    time.Now().Local(),
		Scope: scope,
	})

	if err := m.refreshWithReason(ctx, refreshScope, "trace refresh"); err != nil {
		events.Emit(ctx, events.TraceFailed{
			At:       time.Now().Local(),
			TraceID:  traceID,
			Scope:    scope,
			Duration: time.Since(started),
			Error:    err.Error(),
		})
		return err
	}

	events.Emit(ctx, events.TraceCompleted{
		At:       time.Now().Local(),
		TraceID:  traceID,
		Scope:    scope,
		Duration: time.Since(started),
	})
	return nil
}

func (m *Monitor) refreshWithReason(ctx context.Context, scope RefreshScope, reason string) error {
	switch scope {
	case RefreshScopeInterface:
		return m.RefreshInterface(ctx, reason)
	case RefreshScopeListeners:
		return m.RefreshListeners(ctx, reason)
	case RefreshScopeUpstream:
		return m.RefreshUpstream(ctx, reason)
	case RefreshScopeUnbound:
		return m.RefreshUnbound(ctx, reason)
	case RefreshScopePiHole:
		return m.RefreshPiHole(ctx, reason)
	case RefreshScopeTailscale:
		return m.RefreshTailscale(ctx, reason)
	case RefreshScopeAll:
		fallthrough
	default:
		if err := m.RefreshInterface(ctx, reason); err != nil {
			return err
		}
		if err := m.RefreshListeners(ctx, reason); err != nil {
			return err
		}
		if err := m.RefreshUpstream(ctx, reason); err != nil {
			return err
		}
		if err := m.RefreshUnbound(ctx, reason); err != nil {
			return err
		}
		if err := m.RefreshPiHole(ctx, reason); err != nil {
			return err
		}
		return m.RefreshTailscale(ctx, reason)
	}
}

func formatRefreshScope(scope RefreshScope) string {
	switch scope {
	case RefreshScopeInterface:
		return "interface"
	case RefreshScopeListeners:
		return "listeners"
	case RefreshScopeUpstream:
		return "upstream"
	case RefreshScopeUnbound:
		return "unbound"
	case RefreshScopePiHole:
		return "pihole"
	case RefreshScopeTailscale:
		return "tailscale"
	default:
		return "all"
	}
}

func (m *Monitor) SetDebug(_ context.Context, debug bool) error {
	m.mu.Lock()
	m.debug = debug
	m.mu.Unlock()

	log.Printf("debug events %s", map[bool]string{true: "enabled", false: "disabled"}[debug])
	return nil
}

func (m *Monitor) SetRuntimeStatsInterval(_ context.Context, interval time.Duration) error {
	if interval < 0 {
		return fmt.Errorf("runtime stats interval must be >= 0")
	}

	m.mu.Lock()
	previous := m.runtimeStatsInterval
	running := m.running
	m.runtimeStatsInterval = interval
	m.mu.Unlock()

	if running {
		if err := m.scheduleRuntimeStats(interval); err != nil {
			m.mu.Lock()
			m.runtimeStatsInterval = previous
			m.mu.Unlock()
			return err
		}
	}

	if interval == 0 {
		log.Print("runtime stats reporter disabled")
		return nil
	}
	log.Printf("runtime stats interval updated to %s", interval)
	return nil
}

func orderedChecks(checks model.CheckSet) []model.CheckResult {
	results := make([]model.CheckResult, 0, len(checks))
	seen := make(map[string]struct{}, len(checks))

	for _, key := range model.CheckOrder() {
		result, ok := checks[key]
		if !ok {
			continue
		}
		results = append(results, result)
		seen[key] = struct{}{}
	}

	var extraKeys []string
	for key := range checks {
		if _, ok := seen[key]; ok {
			continue
		}
		extraKeys = append(extraKeys, key)
	}
	sort.Strings(extraKeys)

	for _, key := range extraKeys {
		results = append(results, checks[key])
	}

	return results
}
