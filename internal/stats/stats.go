package stats

import (
	"maps"
	"sync"

	"github.com/kahoon/netmon/internal/events"
)

type OutcomeCounters struct {
	Total   uint64
	Success uint64
	Failure uint64
}

type EventCounters struct {
	Link  uint64
	Addr  uint64
	Route uint64
}

type CollectorCounters struct {
	Started  uint64
	Finished uint64
	Failed   uint64
}

type TaskCounters struct {
	Scheduled   uint64
	Rescheduled uint64
	Executing   uint64
	Executed    uint64
	Cancelled   uint64
	Failed      uint64
}

type CheckCounters struct {
	Evaluations uint64
	Changed     uint64
	Passed      uint64
	Failed      uint64
}

type NotificationCounters struct {
	Sent    uint64
	Skipped uint64
	Failed  uint64
}

type TraceCounters struct {
	Started   uint64
	Completed uint64
	Failed    uint64
}

type Snapshot struct {
	Events        EventCounters
	Collectors    map[string]CollectorCounters
	CollectorRuns map[string]uint64
	Tasks         TaskCounters
	TasksByID     map[string]TaskCounters
	Probes        map[string]OutcomeCounters
	Checks        CheckCounters
	Notifications NotificationCounters
	Traces        TraceCounters
}

type Recorder struct {
	mu            sync.Mutex
	events        EventCounters
	collectors    map[string]CollectorCounters
	collectorRuns map[string]uint64
	tasks         TaskCounters
	tasksByID     map[string]TaskCounters
	probes        map[string]OutcomeCounters
	checks        CheckCounters
	notifications NotificationCounters
	traces        TraceCounters
}

func NewRecorder() *Recorder {
	return &Recorder{
		collectors:    make(map[string]CollectorCounters),
		collectorRuns: make(map[string]uint64),
		tasksByID:     make(map[string]TaskCounters),
		probes:        make(map[string]OutcomeCounters),
	}
}

func (r *Recorder) Handle(event events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch e := event.(type) {
	case events.LinkEvent:
		r.events.Link++
	case events.AddrEvent:
		r.events.Addr++
	case events.RouteEvent:
		r.events.Route++
	case events.CollectorStarted:
		counters := r.collectors[e.Collector]
		counters.Started++
		r.collectors[e.Collector] = counters
		r.collectorRuns[e.Reason]++
	case events.CollectorFinished:
		counters := r.collectors[e.Collector]
		if e.Error != "" {
			counters.Failed++
		} else {
			counters.Finished++
		}
		r.collectors[e.Collector] = counters
	case events.TaskScheduled:
		r.tasks.Scheduled++
		counters := r.tasksByID[e.ID]
		counters.Scheduled++
		r.tasksByID[e.ID] = counters
	case events.TaskRescheduled:
		r.tasks.Rescheduled++
		counters := r.tasksByID[e.ID]
		counters.Rescheduled++
		r.tasksByID[e.ID] = counters
	case events.TaskExecuting:
		r.tasks.Executing++
		counters := r.tasksByID[e.ID]
		counters.Executing++
		r.tasksByID[e.ID] = counters
	case events.TaskExecuted:
		r.tasks.Executed++
		counters := r.tasksByID[e.ID]
		counters.Executed++
		r.tasksByID[e.ID] = counters
	case events.TaskCancelled:
		r.tasks.Cancelled++
		counters := r.tasksByID[e.ID]
		counters.Cancelled++
		r.tasksByID[e.ID] = counters
	case events.TaskFailed:
		r.tasks.Failed++
		counters := r.tasksByID[e.ID]
		counters.Failed++
		r.tasksByID[e.ID] = counters
	case events.ProbeResult:
		key := probeKey(e)
		counters := r.probes[key]
		counters.Total++
		if e.Status == "ok" {
			counters.Success++
		} else {
			counters.Failure++
		}
		r.probes[key] = counters
	case events.ChecksEvaluated:
		r.checks.Evaluations++
		r.checks.Changed += uint64(e.Changed)
		r.checks.Passed += uint64(e.Passed)
		r.checks.Failed += uint64(e.Failed)
	case events.NotificationSent:
		r.notifications.Sent++
	case events.NotificationSkipped:
		r.notifications.Skipped++
	case events.NotificationFailed:
		r.notifications.Failed++
	case events.TraceStarted:
		r.traces.Started++
	case events.TraceCompleted:
		r.traces.Completed++
	case events.TraceFailed:
		r.traces.Failed++
	}
}

func (r *Recorder) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	return Snapshot{
		Events:        r.events,
		Collectors:    maps.Clone(r.collectors),
		CollectorRuns: maps.Clone(r.collectorRuns),
		Tasks:         r.tasks,
		TasksByID:     maps.Clone(r.tasksByID),
		Probes:        maps.Clone(r.probes),
		Checks:        r.checks,
		Notifications: r.notifications,
		Traces:        r.traces,
	}
}

func probeKey(e events.ProbeResult) string {
	if e.Family == "" {
		return e.Kind
	}
	return e.Kind + "/" + e.Family
}
