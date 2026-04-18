package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"time"
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

type sinkKey struct{}
type traceIDKey struct{}

func With(ctx context.Context, traceID string, sink Sink) (withCtx context.Context) {
	withCtx = ctx
	if sink != nil {
		withCtx = context.WithValue(withCtx, sinkKey{}, sink)
	}
	if traceID != "" {
		withCtx = context.WithValue(withCtx, traceIDKey{}, traceID)
	}
	return withCtx
}

func TraceIDAndSinkFromContext(ctx context.Context) (traceID string, sink Sink) {
	if ctx == nil {
		return "", nil
	}
	traceID, _ = ctx.Value(traceIDKey{}).(string)
	sink, _ = ctx.Value(sinkKey{}).(Sink)
	return traceID, sink
}

func Emit(ctx context.Context, kind, message string, fields map[string]string) {
	traceID, sink := TraceIDAndSinkFromContext(ctx)
	if sink == nil {
		return
	}
	cloned := make(map[string]string, len(fields))
	maps.Copy(cloned, fields)
	sink.Emit(Event{
		TraceID: traceID,
		At:      time.Now().Local(),
		Kind:    kind,
		Message: message,
		Fields:  cloned,
	})
}

func NewTraceID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return time.Now().Local().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(raw[:])
}

func TraceCollector[T any](ctx context.Context, name, reason string, fn func(context.Context) (T, error)) (T, error) {
	started := time.Now()
	Emit(ctx, EventCollectorStarted, "collector started", map[string]string{
		"collector": name,
		"reason":    reason,
	})

	value, err := fn(ctx)
	if err != nil {
		var zero T
		return zero, err
	}

	Emit(ctx, EventCollectorFinished, "collector finished", map[string]string{
		"collector": name,
		"reason":    reason,
		"duration":  time.Since(started).String(),
	})
	return value, nil
}

type ProbeResultFields struct {
	Kind      string
	Family    string
	Target    string
	Provider  string
	Status    string
	Latency   time.Duration
	Responder string
	Detail    string
	IP        string
}

func EmitProbeResult(ctx context.Context, result ProbeResultFields) {
	fields := map[string]string{
		"probe_kind": result.Kind,
		"family":     result.Family,
		"status":     result.Status,
	}
	if result.Target != "" {
		fields["target"] = result.Target
	}
	if result.Provider != "" {
		fields["provider"] = result.Provider
	}
	if result.Responder != "" {
		fields["responder"] = result.Responder
	}
	if result.IP != "" {
		fields["ip"] = result.IP
	}
	if result.Latency != 0 {
		fields["latency"] = result.Latency.String()
	}
	if result.Detail != "" {
		fields["detail"] = result.Detail
	}

	Emit(ctx, EventProbeResult, "probe result", fields)
}

func EmitNotificationSent(ctx context.Context, title, severity string) {
	Emit(ctx, EventNotificationSent, "notification sent", map[string]string{
		"title":    title,
		"severity": severity,
	})
}

func EmitNotificationSkipped(ctx context.Context, reason string) {
	Emit(ctx, EventNotificationSkipped, "notification skipped", map[string]string{
		"reason": reason,
	})
}

func EmitChecksChanged(ctx context.Context, reason string, changed int) {
	Emit(ctx, EventChecksChanged, "checks evaluated", map[string]string{
		"reason":  reason,
		"changed": fmt.Sprintf("%d", changed),
	})
}
