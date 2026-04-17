package monitor

import (
	"log"
	"time"
)

type pendingTelemetry struct {
	monitor *Monitor
}

func newPendingTelemetry(m *Monitor) *pendingTelemetry {
	return &pendingTelemetry{monitor: m}
}

func (t *pendingTelemetry) OnScheduled(id string, d time.Duration) {
	event := TaskEvent{
		At:    time.Now().UTC(),
		ID:    id,
		Kind:  TaskEventScheduled,
		Delay: d,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task scheduled: id=%s delay=%s", id, d)
}

func (t *pendingTelemetry) OnRescheduled(id string) {
	event := TaskEvent{
		At:   time.Now().UTC(),
		ID:   id,
		Kind: TaskEventRescheduled,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task rescheduled: id=%s", id)
}

func (t *pendingTelemetry) OnExecuted(id string, duration time.Duration) {
	event := TaskEvent{
		At:       time.Now().UTC(),
		ID:       id,
		Kind:     TaskEventExecuted,
		Duration: duration,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task executed: id=%s duration=%s", id, duration)
}

func (t *pendingTelemetry) OnCancelled(id string) {
	event := TaskEvent{
		At:   time.Now().UTC(),
		ID:   id,
		Kind: TaskEventCancelled,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task cancelled: id=%s", id)
}

func (t *pendingTelemetry) OnFailed(id string, err error) {
	event := TaskEvent{
		At:    time.Now().UTC(),
		ID:    id,
		Kind:  TaskEventFailed,
		Error: err.Error(),
	}
	t.emit(event)
	log.Printf("task failed: id=%s err=%v", id, err)
}

func (t *pendingTelemetry) debugEnabled() bool {
	if t.monitor == nil {
		return false
	}
	t.monitor.mu.Lock()
	defer t.monitor.mu.Unlock()
	return t.monitor.debug
}

func (t *pendingTelemetry) emit(event TaskEvent) {
	if t.monitor == nil {
		return
	}
	t.monitor.broadcastTaskEvent(event)
}
