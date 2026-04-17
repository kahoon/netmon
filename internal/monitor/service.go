package monitor

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/version"
)

type RefreshScope int

const (
	RefreshScopeAll RefreshScope = iota
	RefreshScopeInterface
	RefreshScopeListeners
	RefreshScopeUpstream
)

type Info struct {
	Version              string
	Commit               string
	BuildTime            string
	StartedAt            time.Time
	MonitorInterface     string
	InterfacePoll        time.Duration
	ListenerPoll         time.Duration
	UpstreamPoll         time.Duration
	RuntimeStatsInterval time.Duration
	NtfyHost             string
}

type StatusView struct {
	OverallSeverity model.Severity
	Summary         string
	PublicIPv4      string
	Checks          []model.CheckResult
}

type Service interface {
	GetStatus(ctx context.Context) (StatusView, error)
	WatchStatus(ctx context.Context) (StatusSubscription, error)
	WatchTasks(ctx context.Context) (TaskSubscription, error)
	GetState(ctx context.Context) (model.SystemState, error)
	GetInfo(ctx context.Context) (Info, error)
	Refresh(ctx context.Context, scope RefreshScope) error
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

func (m *Monitor) WatchStatus(_ context.Context) (StatusSubscription, error) {
	return m.subscribeStatus(), nil
}

func (m *Monitor) WatchTasks(_ context.Context) (TaskSubscription, error) {
	return m.subscribeTasks(), nil
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
		RuntimeStatsInterval: runtimeStatsInterval,
		NtfyHost:             m.cfg.NtfyHost,
	}, nil
}

func (m *Monitor) Refresh(ctx context.Context, scope RefreshScope) error {
	switch scope {
	case RefreshScopeInterface:
		return m.RefreshInterface(ctx, "manual refresh")
	case RefreshScopeListeners:
		return m.RefreshListeners(ctx, "manual refresh")
	case RefreshScopeUpstream:
		return m.RefreshUpstream(ctx, "manual refresh")
	case RefreshScopeAll:
		fallthrough
	default:
		if err := m.RefreshInterface(ctx, "manual refresh"); err != nil {
			return err
		}
		if err := m.RefreshListeners(ctx, "manual refresh"); err != nil {
			return err
		}
		return m.RefreshUpstream(ctx, "manual refresh")
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
