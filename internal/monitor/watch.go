package monitor

import (
	"time"

	"github.com/kahoon/netmon/internal/model"
)

type StatusSubscription interface {
	Updates() <-chan StatusView
	Close()
}

type TaskEventKind string

const (
	TaskEventScheduled   TaskEventKind = "scheduled"
	TaskEventRescheduled TaskEventKind = "rescheduled"
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

type TaskSubscription interface {
	Updates() <-chan TaskEvent
	Close()
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

func cloneTaskEvent(event TaskEvent) TaskEvent {
	return event
}
