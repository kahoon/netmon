package monitor

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/kahoon/netmon/internal/collector"
	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/events"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/stats"
	"github.com/kahoon/pending"
)

type Monitor struct {
	cfg      config.Config
	notifier *NtfyNotifier
	mgr      *pending.Manager

	interfaceCollector collector.InterfaceCollector
	listenerCollector  collector.ListenerCollector
	upstreamCollector  collector.UpstreamCollector
	unboundCollector   collector.UnboundCollector
	piholeCollector    *collector.PiHoleCollector
	tailscaleCollector collector.TailscaleCollector

	mu     sync.Mutex
	state  model.SystemState
	checks model.CheckSet

	debug                bool
	startedAt            time.Time
	running              bool
	runtimeStatsInterval time.Duration
	alertHistoryInterval time.Duration

	bus          *events.Hub
	stats        *stats.Recorder
	alertHistory *alertHistory
}

func NewMonitor(cfg config.Config) *Monitor {
	recorder := stats.NewRecorder()
	monitor := &Monitor{
		cfg:                  cfg,
		notifier:             NewNtfyNotifier(cfg),
		interfaceCollector:   collector.InterfaceCollector{},
		listenerCollector:    collector.ListenerCollector{},
		upstreamCollector:    collector.UpstreamCollector{ProbeTimeout: cfg.DNSProbeTimeout},
		unboundCollector:     collector.UnboundCollector{ProbeTimeout: cfg.DNSProbeTimeout},
		piholeCollector:      collector.NewPiHoleCollector(cfg),
		tailscaleCollector:   collector.NewTailscaleCollector(),
		debug:                cfg.DebugEvents,
		startedAt:            time.Now().Local(),
		runtimeStatsInterval: cfg.RuntimeStatsInterval,
		alertHistoryInterval: cfg.AlertHistoryInterval,
		bus: events.NewHub(
			events.FeedConfig{
				Name:   "all",
				Buffer: 64,
			},
			events.FeedConfig{
				Name:    "status",
				Filter:  statusEventsOnly,
				Buffer:  1,
				History: 1,
			},
			events.FeedConfig{
				Name:    "tasks",
				Filter:  taskEventsOnly,
				Buffer:  64,
				History: 64,
			},
			events.FeedConfig{
				Name:    "checks",
				Filter:  checksEventsOnly,
				Buffer:  64,
				History: 64,
			},
		),
		stats:        recorder,
		alertHistory: newAlertHistory(cfg.AlertHistoryInterval),
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
	unbound := m.unboundCollector.Collect(ctx)
	pihole := m.piholeCollector.Collect(ctx)
	tailscale := m.tailscaleCollector.Collect(ctx)
	state := model.SystemState{
		Interface: iface,
		Listeners: listeners,
		Upstream:  upstream,
		Unbound:   unbound,
		PiHole:    pihole,
		Tailscale: tailscale,
	}
	checks := model.EvaluateChecks(m.cfg.ExpectedULA, state)

	m.mu.Lock()
	m.state = state
	m.checks = checks
	m.mu.Unlock()

	log.Printf("initial status: %s", summarizeChecks(checks))
	if state.Upstream.PublicIPv4.OK() {
		log.Printf("initial public IPv4: %s", state.Upstream.PublicIPv4.IP)
	} else if state.Upstream.PublicIPv4.Detail != "" {
		log.Printf("initial public IPv4 lookup failed: %s", state.Upstream.PublicIPv4.Detail)
	}
	if state.Upstream.PublicIPv6.OK() {
		log.Printf("initial public IPv6: %s", state.Upstream.PublicIPv6.IP)
	} else if state.Upstream.PublicIPv6.Detail != "" {
		log.Printf("initial public IPv6 lookup failed: %s", state.Upstream.PublicIPv6.Detail)
	}

	return nil
}

func (m *Monitor) recordAlertAttempt(note Notification, delivered bool, deliveryErr error, at time.Time) {
	attempt := AlertAttempt{
		At:       at,
		Severity: note.Severity,
		Title:    note.Title,
		Reason:   note.Reason,
		Summary:  note.Summary,
	}
	if delivered {
		attempt.DeliveryStatus = AlertDelivered
	} else {
		attempt.DeliveryStatus = AlertNotDelivered
		if deliveryErr != nil {
			attempt.DeliveryError = deliveryErr.Error()
		}
	}
	m.alertHistory.Record(attempt)
}

func (m *Monitor) CurrentLinkIndex() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Interface.LinkIndex
}

func (m *Monitor) RefreshInterface(ctx context.Context, reason string) error {
	ctx = events.WithHub(ctx, m.bus)
	state, err := collectWithEvents(ctx, "interface", reason, func(context.Context) (model.InterfaceState, error) {
		return m.interfaceCollector.Collect(m.cfg.MonitorInterface)
	})
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
	ctx = events.WithHub(ctx, m.bus)
	state, err := collectWithEvents(ctx, "listeners", reason, func(context.Context) (model.ListenerState, error) {
		return m.listenerCollector.Collect()
	})
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
	ctx = events.WithHub(ctx, m.bus)
	state, err := collectWithEvents(ctx, "upstream", reason, func(context.Context) (model.UpstreamState, error) {
		return m.upstreamCollector.Collect(ctx), nil
	})
	if err != nil {
		return err
	}

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.Upstream = state
	})

	return nil
}

func (m *Monitor) RefreshUnbound(ctx context.Context, reason string) error {
	ctx = events.WithHub(ctx, m.bus)
	state, err := collectWithEvents(ctx, "unbound", reason, func(context.Context) (model.UnboundState, error) {
		return m.unboundCollector.Collect(ctx), nil
	})
	if err != nil {
		return err
	}

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.Unbound = state
	})

	return nil
}

func (m *Monitor) RefreshPiHole(ctx context.Context, reason string) error {
	ctx = events.WithHub(ctx, m.bus)
	state, err := collectWithEvents(ctx, "pihole", reason, func(context.Context) (model.PiHoleState, error) {
		return m.piholeCollector.Collect(ctx), nil
	})
	if err != nil {
		return err
	}

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.PiHole = state
	})

	return nil
}

func (m *Monitor) RefreshTailscale(ctx context.Context, reason string) error {
	ctx = events.WithHub(ctx, m.bus)
	state, err := collectWithEvents(ctx, "tailscale", reason, func(context.Context) (model.TailscaleState, error) {
		return m.tailscaleCollector.Collect(ctx), nil
	})
	if err != nil {
		return err
	}

	m.applyUpdate(ctx, reason, func(current *model.SystemState) {
		current.Tailscale = state
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

	ctx = events.WithHub(ctx, m.bus)

	if !statusViewsEqual(previousView, nextView) {
		m.bus.Emit(events.StatusChanged{
			At:     time.Now().Local(),
			Status: cloneStatusView(nextView),
		})
	}

	changedAt := time.Now().Local()
	for _, key := range model.CheckOrder() {
		prev := previousChecks[key]
		curr := nextChecks[key]
		if prev.Equal(curr) {
			continue
		}
		m.bus.Emit(events.CheckChanged{
			At:       changedAt,
			Key:      key,
			Label:    curr.Label,
			Previous: prev,
			Current:  curr,
		})
	}

	changed := changedCheckCount(previousChecks, nextChecks)
	passed, failed := checkOutcomeCounts(nextChecks)
	events.Emit(ctx, events.ChecksEvaluated{
		At:      time.Now().Local(),
		Reason:  reason,
		Changed: changed,
		Passed:  passed,
		Failed:  failed,
	})

	note := BuildChangeNotification(m.cfg, reason, previousState, nextState, previousChecks, nextChecks)
	if note == nil {
		events.Emit(ctx, events.NotificationSkipped{
			At:     time.Now().Local(),
			Reason: "no effective changes",
		})
		return
	}

	if err := m.notifier.Send(ctx, *note); err != nil {
		log.Printf("notify failed: %v", err)
		now := time.Now().Local()
		m.recordAlertAttempt(*note, false, err, now)
		events.Emit(ctx, events.NotificationFailed{
			At:    now,
			Error: err.Error(),
		})
		return
	}

	log.Printf("notification sent: %s", note.Title)
	now := time.Now().Local()
	m.recordAlertAttempt(*note, true, nil, now)
	events.Emit(ctx, events.NotificationSent{
		At:       now,
		Title:    note.Title,
		Severity: note.Severity.String(),
	})
}

func (m *Monitor) notifyError(ctx context.Context, reason string, err error) {
	ctx = events.WithHub(ctx, m.bus)
	log.Printf("%s failed: %v", reason, err)
	note := BuildErrorNotification(m.cfg, reason, err)
	if notifyErr := m.notifier.Send(ctx, note); notifyErr != nil {
		log.Printf("notify failed: %v", notifyErr)
		now := time.Now().Local()
		m.recordAlertAttempt(note, false, notifyErr, now)
		events.Emit(ctx, events.NotificationFailed{
			At:    now,
			Error: notifyErr.Error(),
		})
		return
	}

	log.Printf("notification sent: %s", note.Title)
	now := time.Now().Local()
	m.recordAlertAttempt(note, true, nil, now)
	events.Emit(ctx, events.NotificationSent{
		At:       now,
		Title:    note.Title,
		Severity: note.Severity.String(),
	})
}

func (m *Monitor) subscribeStatus() Subscription[StatusView] {
	m.mu.Lock()
	initial := statusViewFromSnapshot(m.state, m.checks)
	m.mu.Unlock()

	sub := m.bus.Subscribe(
		"status",
		events.WithInitial(events.StatusChanged{
			At:     time.Now().Local(),
			Status: cloneStatusView(initial),
		}),
	)
	return newStatusSubscription(sub)
}

func (m *Monitor) subscribeTasks() Subscription[TaskEvent] {
	sub := m.bus.Subscribe("tasks")
	return newTaskSubscription(sub)
}

func (m *Monitor) subscribeChecks() Subscription[CheckEvent] {
	sub := m.bus.Subscribe("checks")
	return newCheckSubscription(sub)
}

func changedCheckCount(previous, current model.CheckSet) int {
	count := 0
	for _, key := range model.CheckOrder() {
		if previous[key].Equal(current[key]) {
			continue
		}
		count++
	}
	return count
}

func collectWithEvents[T any](ctx context.Context, name, reason string, fn func(context.Context) (T, error)) (T, error) {
	started := time.Now().Local()
	events.Emit(ctx, events.CollectorStarted{
		At:        started,
		Collector: name,
		Reason:    reason,
	})

	value, err := fn(ctx)
	if err != nil {
		events.Emit(ctx, events.CollectorFinished{
			At:        time.Now().Local(),
			Collector: name,
			Reason:    reason,
			Duration:  time.Since(started),
			Error:     err.Error(),
		})
		var zero T
		return zero, err
	}

	events.Emit(ctx, events.CollectorFinished{
		At:        time.Now().Local(),
		Collector: name,
		Reason:    reason,
		Duration:  time.Since(started),
	})
	return value, nil
}

func checkOutcomeCounts(checks model.CheckSet) (passed int, failed int) {
	for _, result := range checks {
		if result.Severity == model.SeverityOK {
			passed++
			continue
		}
		failed++
	}
	return passed, failed
}

func statusEventsOnly(event events.Event) bool {
	_, ok := event.(events.StatusChanged)
	return ok
}

func taskEventsOnly(event events.Event) bool {
	switch event.(type) {
	case events.TaskScheduled, events.TaskRescheduled, events.TaskExecuting, events.TaskExecuted, events.TaskCancelled, events.TaskFailed:
		return true
	default:
		return false
	}
}

func checksEventsOnly(event events.Event) bool {
	_, ok := event.(events.CheckChanged)
	return ok
}
