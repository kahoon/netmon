package monitor

import (
	"sync"
	"time"

	"github.com/kahoon/netmon/internal/events"
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

type taskSubscription struct {
	updates chan TaskEvent
	done    chan struct{}
	close   func()
	once    sync.Once
}

type statusSubscription struct {
	updates chan StatusView
	done    chan struct{}
	close   func()
	once    sync.Once
}

func (s *statusSubscription) Updates() <-chan StatusView {
	return s.updates
}

func (s *statusSubscription) Close() {
	s.once.Do(func() {
		close(s.done)
		if s.close != nil {
			s.close()
		}
	})
}

func (s *taskSubscription) Updates() <-chan TaskEvent {
	return s.updates
}

func (s *taskSubscription) Close() {
	s.once.Do(func() {
		close(s.done)
		if s.close != nil {
			s.close()
		}
	})
}

func newTaskSubscription(sub *events.Subscription) TaskSubscription {
	out := &taskSubscription{
		updates: make(chan TaskEvent, 64),
		done:    make(chan struct{}),
		close:   sub.Close,
	}

	go func() {
		defer close(out.updates)

		for {
			select {
			case <-out.done:
				return
			case event, ok := <-sub.Events():
				if !ok {
					return
				}

				task, ok := taskEventFromDomain(event)
				if !ok {
					continue
				}

				select {
				case out.updates <- task:
				case <-out.done:
					return
				}
			}
		}
	}()

	return out
}

func newStatusSubscription(sub *events.Subscription) StatusSubscription {
	out := &statusSubscription{
		updates: make(chan StatusView, 1),
		done:    make(chan struct{}),
		close:   sub.Close,
	}

	go func() {
		defer close(out.updates)

		for {
			select {
			case <-out.done:
				return
			case event, ok := <-sub.Events():
				if !ok {
					return
				}

				status, ok := statusViewFromDomain(event)
				if !ok {
					continue
				}

				select {
				case out.updates <- status:
				case <-out.done:
					return
				}
			}
		}
	}()

	return out
}

func statusEventsOnly(event events.Event) bool {
	_, ok := event.(events.StatusChanged)
	return ok
}

func statusViewFromDomain(event events.Event) (StatusView, bool) {
	switch e := event.(type) {
	case events.StatusChanged:
		return cloneStatusView(e.Status), true
	default:
		return StatusView{}, false
	}
}

func taskEventsOnly(event events.Event) bool {
	switch event.(type) {
	case events.TaskScheduled, events.TaskRescheduled, events.TaskExecuting, events.TaskExecuted, events.TaskCancelled, events.TaskFailed:
		return true
	default:
		return false
	}
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
