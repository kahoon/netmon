package monitor

import (
	"context"
	"log"
	"time"

	"github.com/kahoon/netmon/internal/events"
	"github.com/kahoon/pending"
	"github.com/vishvananda/netlink"
)

const runtimeStatsTaskID = "runtime:stats"

func (m *Monitor) Run(ctx context.Context) error {
	ctx = events.WithHub(ctx, m.bus)
	// Start the stats consumer to process events and update metrics.
	m.startStatsConsumer(ctx)
	// Mark the monitor as running, and capture the initial stats interval for scheduling the first stats reporter.
	m.mu.Lock()
	m.running = true
	initialStatsInterval := m.runtimeStatsInterval
	m.mu.Unlock()

	// netlink subscription channels for the monitored interface.
	linkUpdates := make(chan netlink.LinkUpdate, 32)
	addrUpdates := make(chan netlink.AddrUpdate, 64)
	routeUpdates := make(chan netlink.RouteUpdate, 64)
	done := make(chan struct{})
	defer close(done)
	// Ensure all pending tasks are stopped when the scheduler exits.
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.mgr.Shutdown(shutdownCtx)
	}()

	// Subscribe to netlink updates for the monitored interface.
	if err := netlink.LinkSubscribe(linkUpdates, done); err != nil {
		return err
	}
	if err := netlink.AddrSubscribe(addrUpdates, done); err != nil {
		return err
	}
	if err := netlink.RouteSubscribe(routeUpdates, done); err != nil {
		return err
	}

	// Start a periodic reporter for runtime stats.
	if err := m.scheduleRuntimeStats(initialStatsInterval); err != nil {
		log.Printf("run stats reporter: %v", err)
	}
	// Debounce interface events.
	scheduleInterfaceRefresh := func(reason string) {
		_, err := m.mgr.ScheduleWith(
			"refresh:interface:event:"+m.cfg.MonitorInterface,
			func(taskCtx context.Context) error {
				return m.RefreshInterface(taskCtx, reason)
			},
			pending.ScheduleOptions{Delay: m.cfg.NetlinkDebounce},
		)
		if err != nil {
			log.Printf("schedule interface refresh failed: %v", err)
		}
	}
	// Schedule state refresh, but skip if a previous refresh is still running.
	scheduleSkipIfRunning := func(key, reason string, task func(context.Context, string) error) {
		_, err := m.mgr.ScheduleWith(
			key,
			func(taskCtx context.Context) error {
				return task(taskCtx, reason)
			},
			pending.ScheduleOptions{SkipIfRunning: true},
		)
		if err != nil {
			log.Printf("schedule %s failed: %v", key, err)
		}
	}
	// Refresh timers.
	interfaceTicker := time.NewTicker(m.cfg.InterfacePollInterval)
	listenerTicker := time.NewTicker(m.cfg.ListenerPollInterval)
	upstreamTicker := time.NewTicker(m.cfg.UpstreamPollInterval)
	unboundTicker := time.NewTicker(m.cfg.UnboundPollInterval)
	defer interfaceTicker.Stop()
	defer listenerTicker.Stop()
	defer upstreamTicker.Stop()
	defer unboundTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Print("shutting down")
			return nil

		case upd := <-linkUpdates:
			if upd.Attrs().Name != m.cfg.MonitorInterface {
				continue
			}
			events.Emit(ctx, events.LinkEvent{At: time.Now().Local()})
			if m.debug {
				log.Printf("link event: if=%s oper=%s flags=%s", upd.Attrs().Name, upd.Attrs().OperState.String(), upd.Attrs().Flags.String())
			}
			scheduleInterfaceRefresh("link update")

		case upd := <-addrUpdates:
			if upd.LinkIndex != m.CurrentLinkIndex() {
				continue
			}
			if upd.LinkAddress.IP == nil {
				continue
			}
			events.Emit(ctx, events.AddrEvent{At: time.Now().Local()})
			if m.debug {
				log.Printf("addr event: new=%t addr=%s", upd.NewAddr, upd.LinkAddress.String())
			}
			scheduleInterfaceRefresh("address update")

		case upd := <-routeUpdates:
			if upd.LinkIndex != m.CurrentLinkIndex() {
				continue
			}
			events.Emit(ctx, events.RouteEvent{At: time.Now().Local()})
			if m.debug {
				log.Printf("route event: type=%d dst=%v gw=%v", upd.Type, upd.Dst, upd.Gw)
			}
			scheduleInterfaceRefresh("route update")

		case <-interfaceTicker.C:
			scheduleSkipIfRunning("refresh:interface:poll", "interface poll", m.RefreshInterface)

		case <-listenerTicker.C:
			scheduleSkipIfRunning("refresh:listeners", "listener poll", m.RefreshListeners)

		case <-upstreamTicker.C:
			scheduleSkipIfRunning("refresh:upstream", "upstream poll", m.RefreshUpstream)

		case <-unboundTicker.C:
			scheduleSkipIfRunning("refresh:unbound", "unbound poll", m.RefreshUnbound)
		}
	}
}

func (m *Monitor) startStatsConsumer(ctx context.Context) {
	sub := m.bus.Subscribe(events.WithoutReplay())
	go func() {
		defer sub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-sub.Events():
				if !ok {
					return
				}
				m.stats.Handle(event)
			}
		}
	}()
}

func (m *Monitor) scheduleRuntimeStats(interval time.Duration) error {
	// Cancel any existing stats task before scheduling a new one.
	m.mgr.Cancel(runtimeStatsTaskID)
	// If the interval is zero, runtimestats are disabled.
	if interval == 0 {
		return nil
	}
	// Schedule a new stats task with the updated interval.
	_, err := m.mgr.ScheduleWith(
		runtimeStatsTaskID,
		func(taskCtx context.Context) error {
			return runtimeStatsReporter(taskCtx, interval)
		},
		pending.ScheduleOptions{},
	)
	return err
}
