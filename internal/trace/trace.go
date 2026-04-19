package trace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"time"

	"github.com/kahoon/netmon/internal/events"
)

const (
	EventTraceStarted        = "trace_started"
	EventRefreshRequested    = "refresh_requested"
	EventCollectorStarted    = "collector_started"
	EventCollectorFinished   = "collector_finished"
	EventProbeResult         = "probe_result"
	EventChecksChanged       = "checks_changed"
	EventNotificationSent    = "notification_sent"
	EventNotificationSkipped = "notification_skipped"
	EventTraceCompleted      = "trace_completed"
	EventTraceFailed         = "trace_failed"
)

type Event struct {
	TraceID string
	At      time.Time
	Kind    string
	Message string
	Fields  map[string]string
}

type Sink interface {
	Emit(Event)
}

type FormatterSink struct {
	traceID string
	sink    Sink
}

func NewFormatterSink(traceID string, sink Sink) *FormatterSink {
	return &FormatterSink{
		traceID: traceID,
		sink:    sink,
	}
}

func (s *FormatterSink) Handle(event events.Event) {
	if s == nil || s.sink == nil {
		return
	}

	formatted, ok := formatEvent(s.traceID, event)
	if !ok {
		return
	}
	s.sink.Emit(formatted)
}

func NewTraceID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return time.Now().Local().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(raw[:])
}

func formatEvent(traceID string, event events.Event) (Event, bool) {
	switch e := event.(type) {
	case events.TraceStarted:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventTraceStarted,
			Message: "trace started",
			Fields: map[string]string{
				"scope": e.Scope,
			},
		}, true
	case events.RefreshRequested:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventRefreshRequested,
			Message: "refresh requested",
			Fields: map[string]string{
				"scope": e.Scope,
			},
		}, true
	case events.CollectorStarted:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventCollectorStarted,
			Message: "collector started",
			Fields: map[string]string{
				"collector": e.Collector,
				"reason":    e.Reason,
			},
		}, true
	case events.CollectorFinished:
		fields := map[string]string{
			"collector": e.Collector,
			"reason":    e.Reason,
			"duration":  e.Duration.String(),
		}
		if e.Error != "" {
			fields["error"] = e.Error
		}
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventCollectorFinished,
			Message: "collector finished",
			Fields:  fields,
		}, true
	case events.ProbeResult:
		fields := map[string]string{
			"probe_kind": e.Kind,
			"family":     e.Family,
			"status":     e.Status,
		}
		if e.Target != "" {
			fields["target"] = e.Target
		}
		if e.Provider != "" {
			fields["provider"] = e.Provider
		}
		if e.Responder != "" {
			fields["responder"] = e.Responder
		}
		if e.IP != "" {
			fields["ip"] = e.IP
		}
		if e.Latency != 0 {
			fields["latency"] = e.Latency.String()
		}
		if e.Detail != "" {
			fields["detail"] = e.Detail
		}
		if e.Rcode != "" {
			fields["rcode"] = e.Rcode
		}
		if e.AD {
			fields["ad"] = "true"
		}
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventProbeResult,
			Message: "probe result",
			Fields:  fields,
		}, true
	case events.ChecksEvaluated:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventChecksChanged,
			Message: "checks evaluated",
			Fields: map[string]string{
				"reason":  e.Reason,
				"changed": fmt.Sprintf("%d", e.Changed),
				"passed":  fmt.Sprintf("%d", e.Passed),
				"failed":  fmt.Sprintf("%d", e.Failed),
			},
		}, true
	case events.NotificationSent:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventNotificationSent,
			Message: "notification sent",
			Fields: map[string]string{
				"title":    e.Title,
				"severity": e.Severity,
			},
		}, true
	case events.NotificationSkipped:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventNotificationSkipped,
			Message: "notification skipped",
			Fields: map[string]string{
				"reason": e.Reason,
			},
		}, true
	case events.NotificationFailed:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    "notification_failed",
			Message: "notification failed",
			Fields: map[string]string{
				"error": e.Error,
			},
		}, true
	case events.TraceCompleted:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventTraceCompleted,
			Message: "trace completed",
			Fields: map[string]string{
				"scope":    e.Scope,
				"duration": e.Duration.String(),
			},
		}, true
	case events.TraceFailed:
		return Event{
			TraceID: traceID,
			At:      e.At,
			Kind:    EventTraceFailed,
			Message: "trace failed",
			Fields: map[string]string{
				"scope":    e.Scope,
				"duration": e.Duration.String(),
				"error":    e.Error,
			},
		}, true
	default:
		return Event{}, false
	}
}

func cloneFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(fields))
	maps.Copy(cloned, fields)
	return cloned
}
