package events

import (
	"time"

	"github.com/kahoon/netmon/internal/model"
)

type Event interface {
	event()
	OccurredAt() time.Time
}

type StatusView struct {
	OverallSeverity model.Severity
	Summary         string
	PublicIPv4      string
	PublicIPv6      string
	Checks          []model.CheckResult
}

type StatusChanged struct {
	At     time.Time
	Status StatusView
}

func (StatusChanged) event() {}

func (e StatusChanged) OccurredAt() time.Time {
	return e.At
}

type TraceStarted struct {
	At      time.Time
	TraceID string
	Scope   string
}

func (TraceStarted) event() {}

func (e TraceStarted) OccurredAt() time.Time {
	return e.At
}

type RefreshRequested struct {
	At    time.Time
	Scope string
}

func (RefreshRequested) event() {}

func (e RefreshRequested) OccurredAt() time.Time {
	return e.At
}

type TraceCompleted struct {
	At       time.Time
	TraceID  string
	Scope    string
	Duration time.Duration
}

func (TraceCompleted) event() {}

func (e TraceCompleted) OccurredAt() time.Time {
	return e.At
}

type TraceFailed struct {
	At       time.Time
	TraceID  string
	Scope    string
	Duration time.Duration
	Error    string
}

func (TraceFailed) event() {}

func (e TraceFailed) OccurredAt() time.Time {
	return e.At
}

type CollectorStarted struct {
	At        time.Time
	Collector string
	Reason    string
}

func (CollectorStarted) event() {}

func (e CollectorStarted) OccurredAt() time.Time {
	return e.At
}

type CollectorFinished struct {
	At        time.Time
	Collector string
	Reason    string
	Duration  time.Duration
	Error     string
}

func (CollectorFinished) event() {}

func (e CollectorFinished) OccurredAt() time.Time {
	return e.At
}

type ProbeResult struct {
	At        time.Time
	Kind      string
	Family    string
	Target    string
	Provider  string
	Status    string
	Latency   time.Duration
	Responder string
	Detail    string
	IP        string
	Rcode     string
	AD        bool
}

func (ProbeResult) event() {}

func (e ProbeResult) OccurredAt() time.Time {
	return e.At
}

type ChecksEvaluated struct {
	At      time.Time
	Reason  string
	Changed int
	Passed  int
	Failed  int
}

func (ChecksEvaluated) event() {}

func (e ChecksEvaluated) OccurredAt() time.Time {
	return e.At
}

type CheckChanged struct {
	At       time.Time
	Key      string
	Label    string
	Previous model.CheckResult
	Current  model.CheckResult
}

func (CheckChanged) event() {}

func (e CheckChanged) OccurredAt() time.Time {
	return e.At
}

type NotificationSent struct {
	At       time.Time
	Title    string
	Severity string
}

func (NotificationSent) event() {}

func (e NotificationSent) OccurredAt() time.Time {
	return e.At
}

type NotificationSkipped struct {
	At     time.Time
	Reason string
}

func (NotificationSkipped) event() {}

func (e NotificationSkipped) OccurredAt() time.Time {
	return e.At
}

type NotificationFailed struct {
	At    time.Time
	Error string
}

func (NotificationFailed) event() {}

func (e NotificationFailed) OccurredAt() time.Time {
	return e.At
}

type TaskScheduled struct {
	At    time.Time
	ID    string
	Delay time.Duration
}

func (TaskScheduled) event() {}

func (e TaskScheduled) OccurredAt() time.Time {
	return e.At
}

type TaskRescheduled struct {
	At time.Time
	ID string
}

func (TaskRescheduled) event() {}

func (e TaskRescheduled) OccurredAt() time.Time {
	return e.At
}

type TaskExecuting struct {
	At time.Time
	ID string
}

func (TaskExecuting) event() {}

func (e TaskExecuting) OccurredAt() time.Time {
	return e.At
}

type TaskExecuted struct {
	At       time.Time
	ID       string
	Duration time.Duration
}

func (TaskExecuted) event() {}

func (e TaskExecuted) OccurredAt() time.Time {
	return e.At
}

type TaskCancelled struct {
	At time.Time
	ID string
}

func (TaskCancelled) event() {}

func (e TaskCancelled) OccurredAt() time.Time {
	return e.At
}

type TaskFailed struct {
	At    time.Time
	ID    string
	Error string
}

func (TaskFailed) event() {}

func (e TaskFailed) OccurredAt() time.Time {
	return e.At
}

type LinkEvent struct {
	At time.Time
}

func (LinkEvent) event() {}

func (e LinkEvent) OccurredAt() time.Time {
	return e.At
}

type AddrEvent struct {
	At time.Time
}

func (AddrEvent) event() {}

func (e AddrEvent) OccurredAt() time.Time {
	return e.At
}

type RouteEvent struct {
	At time.Time
}

func (RouteEvent) event() {}

func (e RouteEvent) OccurredAt() time.Time {
	return e.At
}
