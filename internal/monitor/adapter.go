package monitor

import (
	"time"

	"github.com/kahoon/netmon/internal/events"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/stats"
)

// Adapter types and functions to translate between domain models and service API models.
type SystemState = model.SystemState
type StatsSnapshot = stats.Snapshot

// RefreshScope defines the scope of a refresh or trace operation.
type RefreshScope int

const (
	RefreshScopeAll RefreshScope = iota
	RefreshScopeInterface
	RefreshScopeListeners
	RefreshScopeUpstream
	RefreshScopeUnbound
	RefreshScopePiHole
	RefreshScopeTailscale
)

// Info contains static information about the monitor instance.
type Info struct {
	Version              string
	Commit               string
	BuildTime            string
	StartedAt            time.Time
	MonitorInterface     string
	InterfacePoll        time.Duration
	ListenerPoll         time.Duration
	UpstreamPoll         time.Duration
	UnboundPoll          time.Duration
	PiHolePoll           time.Duration
	TailscalePoll        time.Duration
	RuntimeStatsInterval time.Duration
	AlertHistoryInterval time.Duration
	NtfyHost             string
}

// StatusView is a snapshot of the current status of the system, including overall severity, summary, public IPs, and individual check results.
type StatusView = events.StatusView

func newStatusSubscription(sub *events.Subscription) Subscription[StatusView] {
	return newSubscription(sub, 1, statusViewFromDomain)
}

func statusViewFromDomain(event events.Event) (StatusView, bool) {
	if statusEventsOnly(event) {
		return cloneStatusView(event.(events.StatusChanged).Status), true
	} else {
		return StatusView{}, false
	}
}

func statusViewFromSnapshot(state model.SystemState, checks model.CheckSet) StatusView {
	return StatusView{
		OverallSeverity: model.CurrentHealthSeverity(checks),
		Summary:         summarizeChecks(checks),
		PublicIPv4:      state.Upstream.PublicIPv4.IP,
		PublicIPv6:      state.Upstream.PublicIPv6.IP,
		Checks:          orderedChecks(checks),
	}
}

func cloneStatusView(view StatusView) StatusView {
	cloned := view
	cloned.Checks = append([]model.CheckResult(nil), view.Checks...)
	return cloned
}

func statusViewsEqual(a, b StatusView) bool {
	if a.OverallSeverity != b.OverallSeverity || a.Summary != b.Summary || a.PublicIPv4 != b.PublicIPv4 || a.PublicIPv6 != b.PublicIPv6 {
		return false
	}
	if len(a.Checks) != len(b.Checks) {
		return false
	}
	for i := range a.Checks {
		if !a.Checks[i].Equal(b.Checks[i]) {
			return false
		}
	}
	return true
}

// TaskEvent represents an event related to a scheduled task, such as when it is scheduled, rescheduled, executed, cancelled, or failed.
type TaskEventKind string

const (
	TaskEventScheduled   TaskEventKind = "scheduled"
	TaskEventRescheduled TaskEventKind = "rescheduled"
	TaskEventExecuting   TaskEventKind = "executing"
	TaskEventExecuted    TaskEventKind = "executed"
	TaskEventCancelled   TaskEventKind = "cancelled"
	TaskEventFailed      TaskEventKind = "failed"
)

type TaskEvent struct {
	At       time.Time
	ID       string
	Kind     TaskEventKind
	Delay    time.Duration
	Duration time.Duration
	Error    string
}

func newTaskSubscription(sub *events.Subscription) Subscription[TaskEvent] {
	return newSubscription(sub, 64, taskEventFromDomain)
}

func taskEventFromDomain(event events.Event) (TaskEvent, bool) {
	switch e := event.(type) {
	case events.TaskScheduled:
		return TaskEvent{
			At:    e.At,
			ID:    e.ID,
			Kind:  TaskEventScheduled,
			Delay: e.Delay,
		}, true
	case events.TaskRescheduled:
		return TaskEvent{
			At:   e.At,
			ID:   e.ID,
			Kind: TaskEventRescheduled,
		}, true
	case events.TaskExecuting:
		return TaskEvent{
			At:   e.At,
			ID:   e.ID,
			Kind: TaskEventExecuting,
		}, true
	case events.TaskExecuted:
		return TaskEvent{
			At:       e.At,
			ID:       e.ID,
			Kind:     TaskEventExecuted,
			Duration: e.Duration,
		}, true
	case events.TaskCancelled:
		return TaskEvent{
			At:   e.At,
			ID:   e.ID,
			Kind: TaskEventCancelled,
		}, true
	case events.TaskFailed:
		return TaskEvent{
			At:    e.At,
			ID:    e.ID,
			Kind:  TaskEventFailed,
			Error: e.Error,
		}, true
	default:
		return TaskEvent{}, false
	}
}

// CheckEvent represents a change in the status of a health check, including the previous and current severity, summary, and detail.
type CheckEvent struct {
	At               time.Time
	Key              string
	Label            string
	PreviousSeverity model.Severity
	PreviousSummary  string
	PreviousDetail   string
	CurrentSeverity  model.Severity
	CurrentSummary   string
	CurrentDetail    string
}

func newCheckSubscription(sub *events.Subscription) Subscription[CheckEvent] {
	return newSubscription(sub, 64, checkEventFromDomain)
}

func checkEventFromDomain(event events.Event) (CheckEvent, bool) {
	switch e := event.(type) {
	case events.CheckChanged:
		return CheckEvent{
			At:               e.At,
			Key:              e.Key,
			Label:            e.Label,
			PreviousSeverity: e.Previous.Severity,
			PreviousSummary:  e.Previous.Summary,
			PreviousDetail:   e.Previous.Detail,
			CurrentSeverity:  e.Current.Severity,
			CurrentSummary:   e.Current.Summary,
			CurrentDetail:    e.Current.Detail,
		}, true
	default:
		return CheckEvent{}, false
	}
}
