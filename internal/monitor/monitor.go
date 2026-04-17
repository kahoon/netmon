package monitor

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/kahoon/netmon/internal/collector"
	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/pending"
)

type Monitor struct {
	cfg      config.Config
	notifier *NtfyNotifier
	mgr      *pending.Manager

	interfaceCollector collector.InterfaceCollector
	listenerCollector  collector.ListenerCollector
	upstreamCollector  collector.UpstreamCollector

	mu     sync.Mutex
	state  model.SystemState
	checks model.CheckSet

	debug                bool
	startedAt            time.Time
	running              bool
	runtimeStatsInterval time.Duration

	statusBroadcaster *broadcaster[StatusView]
	taskBroadcaster   *broadcaster[TaskEvent]
}

func NewMonitor(cfg config.Config) *Monitor {
	monitor := &Monitor{
		cfg:                cfg,
		notifier:           NewNtfyNotifier(cfg),
		interfaceCollector: collector.InterfaceCollector{},
		listenerCollector:  collector.ListenerCollector{},
		upstreamCollector: collector.UpstreamCollector{
			RootServersV4:    cfg.RootServersV4,
			RootServersV6:    cfg.RootServersV6,
			PublicIPResolver: cfg.PublicIPResolver,
			PublicIPName:     cfg.PublicIPName,
			ProbeTimeout:     cfg.DNSProbeTimeout,
		},
		debug:                cfg.DebugEvents,
		startedAt:            time.Now().UTC(),
		runtimeStatsInterval: cfg.RuntimeStatsInterval,

		statusBroadcaster: newBroadcaster[StatusView](
			withBuffer[StatusView](1),
			withClone[StatusView](cloneStatusView),
			withOverflow[StatusView](overflowReplace),
		),
		taskBroadcaster: newBroadcaster[TaskEvent](
			withBuffer[TaskEvent](64),
			withClone[TaskEvent](cloneTaskEvent),
			withOverflow[TaskEvent](overflowDropOldest),
			withHistory[TaskEvent](64),
		),
	}
	// Initialize the pending manager with a telemetry implementation that reports to the monitor's logger.
	// This allows us to track pending operations and their durations.
	telemetry := newPendingTelemetry(monitor)
	monitor.mgr = pending.NewManager(pending.WithLogger(telemetry))
	return monitor
}

func (m *Monitor) Initialize(ctx context.Context) error {
	iface, err := m.interfaceCollector.Collect(m.cfg.MonitorInterface)
	if err != nil {
		return err
	}

	listeners, err := m.listenerCollector.Collect()
	if err != nil {
		return err
	}

	upstream := m.upstreamCollector.Collect(ctx)
	state := model.SystemState{
		Interface: iface,
		Listeners: listeners,
		Upstream:  upstream,
	}
	checks := model.EvaluateChecks(m.cfg.ExpectedULA, state)

	m.mu.Lock()
	m.state = state
	m.checks = checks
	m.mu.Unlock()

	log.Printf("initial status: %s", summarizeChecks(checks))
	if state.Upstream.PublicIPv4.IPv4 != "" {
		log.Printf("initial public IPv4: %s", state.Upstream.PublicIPv4.IPv4)
	} else if state.Upstream.PublicIPv4.Error != "" {
		log.Printf("initial public IPv4 lookup failed: %s", state.Upstream.PublicIPv4.Error)
	}

	return nil
}

func (m *Monitor) CurrentLinkIndex() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Interface.LinkIndex
}

func (m *Monitor) RefreshInterface(ctx context.Context, reason string) error {
	state, err := m.interfaceCollector.Collect(m.cfg.MonitorInterface)
	if err != nil {
		m.notifyError(ctx, reason, err)
		return err
	}

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.Interface = state
	})

	return nil
}

func (m *Monitor) RefreshListeners(ctx context.Context, reason string) error {
	state, err := m.listenerCollector.Collect()
	if err != nil {
		m.notifyError(ctx, reason, err)
		return err
	}

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.Listeners = state
	})

	return nil
}

func (m *Monitor) RefreshUpstream(ctx context.Context, reason string) error {
	state := m.upstreamCollector.Collect(ctx)

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.Upstream = state
	})

	return nil
}

func (m *Monitor) applyUpdate(ctx context.Context, reason string, update func(*model.SystemState)) {
	m.mu.Lock()
	previousState := m.state
	previousChecks := model.CopyCheckSet(m.checks)
	previousView := statusViewFromSnapshot(previousState, previousChecks)

	nextState := m.state
	update(&nextState)
	nextChecks := model.EvaluateChecks(m.cfg.ExpectedULA, nextState)
	nextView := statusViewFromSnapshot(nextState, nextChecks)

	m.state = nextState
	m.checks = nextChecks
	m.mu.Unlock()

	if !statusViewsEqual(previousView, nextView) {
		m.broadcastStatus(nextView)
	}

	note := BuildChangeNotification(m.cfg, reason, previousState, nextState, previousChecks, nextChecks)
	if note == nil {
		return
	}

	if err := m.notifier.Send(ctx, *note); err != nil {
		log.Printf("notify failed: %v", err)
		return
	}

	log.Printf("notification sent: %s", note.Title)
}

func (m *Monitor) notifyError(ctx context.Context, reason string, err error) {
	log.Printf("%s failed: %v", reason, err)
	note := BuildErrorNotification(m.cfg, reason, err)
	if notifyErr := m.notifier.Send(ctx, note); notifyErr != nil {
		log.Printf("notify failed: %v", notifyErr)
	}
}

func (m *Monitor) subscribeStatus() StatusSubscription {
	m.mu.Lock()
	initial := statusViewFromSnapshot(m.state, m.checks)
	m.mu.Unlock()

	return m.statusBroadcaster.Subscribe(initial)
}

func (m *Monitor) broadcastStatus(view StatusView) {
	m.statusBroadcaster.Broadcast(view)
}

func (m *Monitor) subscribeTasks() TaskSubscription {
	return m.taskBroadcaster.Subscribe()
}

func (m *Monitor) broadcastTaskEvent(event TaskEvent) {
	m.taskBroadcaster.Broadcast(event)
}
