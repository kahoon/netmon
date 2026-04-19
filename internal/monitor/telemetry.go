package monitor

import (
	"log"
	"time"

	"github.com/kahoon/netmon/internal/events"
)

type pendingTelemetry struct {
	monitor *Monitor
}

func newPendingTelemetry(m *Monitor) *pendingTelemetry {
	return &pendingTelemetry{monitor: m}
}

func (t *pendingTelemetry) OnScheduled(id string, d time.Duration) {
	event := events.TaskScheduled{
		At:    time.Now().Local(),
		ID:    id,
		Delay: d,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task scheduled: id=%s delay=%s", id, d)
}

func (t *pendingTelemetry) OnRescheduled(id string) {
	event := events.TaskRescheduled{
		At: time.Now().Local(),
		ID: id,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task rescheduled: id=%s", id)
}

func (t *pendingTelemetry) OnExecuting(id string) {
	event := events.TaskExecuting{
		At: time.Now().Local(),
		ID: id,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task executing: id=%s", id)
}

func (t *pendingTelemetry) OnExecuted(id string, duration time.Duration) {
	event := events.TaskExecuted{
		At:       time.Now().Local(),
		ID:       id,
		Duration: duration,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task executed: id=%s duration=%s", id, duration)
}

func (t *pendingTelemetry) OnCancelled(id string) {
	event := events.TaskCancelled{
		At: time.Now().Local(),
		ID: id,
	}
	t.emit(event)
	if !t.debugEnabled() {
		return
	}
	log.Printf("task cancelled: id=%s", id)
}

func (t *pendingTelemetry) OnFailed(id string, err error) {
	event := events.TaskFailed{
		At:    time.Now().Local(),
		ID:    id,
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

func (t *pendingTelemetry) emit(event events.Event) {
	if t.monitor == nil {
		return
	}
	t.monitor.bus.Emit(event)
}
