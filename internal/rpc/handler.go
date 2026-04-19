package rpc

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/netmon/internal/monitor"
	"github.com/kahoon/netmon/internal/stats"
	"github.com/kahoon/netmon/internal/trace"
	netmonv1 "github.com/kahoon/netmon/proto/netmon/v1"
	netmonv1connect "github.com/kahoon/netmon/proto/netmon/v1/netmonv1connect"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Handler struct {
	svc monitor.Service
}

var _ netmonv1connect.NetmonServiceHandler = (*Handler)(nil)

func NewHandler(svc monitor.Service, opts ...connect.HandlerOption) (string, http.Handler) {
	return netmonv1connect.NewNetmonServiceHandler(&Handler{svc: svc}, opts...)
}

func (h *Handler) GetStatus(ctx context.Context, _ *connect.Request[netmonv1.GetStatusRequest]) (*connect.Response[netmonv1.GetStatusResponse], error) {
	status, err := h.svc.GetStatus(ctx)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(mapStatusView(status)), nil
}

func (h *Handler) WatchStatus(ctx context.Context, _ *connect.Request[netmonv1.WatchStatusRequest], stream *connect.ServerStream[netmonv1.WatchStatusResponse]) error {
	sub, err := h.svc.WatchStatus(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		case status, ok := <-sub.Updates():
			if !ok {
				return nil
			}
			if err := stream.Send(&netmonv1.WatchStatusResponse{
				Status: mapStatusView(status),
			}); err != nil {
				return err
			}
		}
	}
}

func (h *Handler) WatchTasks(ctx context.Context, _ *connect.Request[netmonv1.WatchTasksRequest], stream *connect.ServerStream[netmonv1.WatchTasksResponse]) error {
	sub, err := h.svc.WatchTasks(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-sub.Updates():
			if !ok {
				return nil
			}
			if err := stream.Send(&netmonv1.WatchTasksResponse{
				Event: mapTaskEvent(event),
			}); err != nil {
				return err
			}
		}
	}
}

func (h *Handler) Trace(ctx context.Context, req *connect.Request[netmonv1.TraceRequest], stream *connect.ServerStream[netmonv1.TraceResponse]) error {
	scope, err := mapRefreshScope(req.Msg.GetScope())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	sink := trace.NewChannelSink(ctx, 128)
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.svc.Trace(ctx, scope, sink)
		sink.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-sink.Events():
			if !ok {
				if err := <-errCh; err != nil {
					return err
				}
				return nil
			}
			if err := stream.Send(&netmonv1.TraceResponse{Event: mapTraceEvent(event)}); err != nil {
				return err
			}
		}
	}
}

func (h *Handler) GetState(ctx context.Context, _ *connect.Request[netmonv1.GetStateRequest]) (*connect.Response[netmonv1.GetStateResponse], error) {
	state, err := h.svc.GetState(ctx)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&netmonv1.GetStateResponse{
		Interface: &netmonv1.InterfaceState{
			Name:      state.Interface.IfName,
			LinkIndex: int32(state.Interface.LinkIndex),
			LinkUp:    state.Interface.LinkUp,
			OperState: state.Interface.OperState,
			Ula:       slices.Clone(state.Interface.ULA),
			Gua:       slices.Clone(state.Interface.GUA),
			UsableGua: slices.Clone(state.Interface.UsableGUA),
		},
		Listeners: &netmonv1.ListenerState{
			Dns53Tcp:        mapSocketProbe(state.Listeners.DNS53TCP),
			Dns53Udp:        mapSocketProbe(state.Listeners.DNS53UDP),
			Resolver5335Tcp: mapSocketProbe(state.Listeners.Resolver5335TCP),
			Resolver5335Udp: mapSocketProbe(state.Listeners.Resolver5335UDP),
		},
		Upstream: &netmonv1.UpstreamState{
			RootV4:      mapDNSProbe(state.Upstream.RootDNSV4),
			RootV6:      mapDNSProbe(state.Upstream.RootDNSV6),
			RecursiveV4: mapDNSProbe(state.Upstream.RecursiveDNSV4),
			RecursiveV6: mapDNSProbe(state.Upstream.RecursiveDNSV6),
			PublicIpv4:  mapPublicIPObservation(state.Upstream.PublicIPv4),
			PublicIpv6:  mapPublicIPObservation(state.Upstream.PublicIPv6),
			Dnssec:      mapDNSSECProbeResult(state.Upstream.DNSSEC),
		},
	}), nil
}

func (h *Handler) GetInfo(ctx context.Context, _ *connect.Request[netmonv1.GetInfoRequest]) (*connect.Response[netmonv1.GetInfoResponse], error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&netmonv1.GetInfoResponse{
		Version:              info.Version,
		StartedAtUnix:        info.StartedAt.Unix(),
		MonitorInterface:     info.MonitorInterface,
		InterfacePoll:        info.InterfacePoll.String(),
		ListenerPoll:         info.ListenerPoll.String(),
		UpstreamPoll:         info.UpstreamPoll.String(),
		RuntimeStatsInterval: info.RuntimeStatsInterval.String(),
		NtfyHost:             info.NtfyHost,
		Commit:               info.Commit,
		BuildTime:            info.BuildTime,
	}), nil
}

func (h *Handler) GetStats(ctx context.Context, _ *connect.Request[netmonv1.GetStatsRequest]) (*connect.Response[netmonv1.GetStatsResponse], error) {
	snapshot, err := h.svc.GetStats(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(mapStatsSnapshot(snapshot)), nil
}

func (h *Handler) Refresh(ctx context.Context, req *connect.Request[netmonv1.RefreshRequest]) (*connect.Response[netmonv1.RefreshResponse], error) {
	scope, err := mapRefreshScope(req.Msg.GetScope())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.svc.Refresh(ctx, scope); err != nil {
		return nil, err
	}
	return connect.NewResponse(&netmonv1.RefreshResponse{}), nil
}

func (h *Handler) SetDebug(ctx context.Context, req *connect.Request[netmonv1.SetDebugRequest]) (*connect.Response[netmonv1.SetDebugResponse], error) {
	debug := req.Msg.GetDebug()
	h.svc.SetDebug(ctx, debug)
	return connect.NewResponse(&netmonv1.SetDebugResponse{}), nil
}

func (h *Handler) SetRuntimeStatsInterval(ctx context.Context, req *connect.Request[netmonv1.SetRuntimeStatsIntervalRequest]) (*connect.Response[netmonv1.SetRuntimeStatsIntervalResponse], error) {
	interval, err := parseProtoDuration(req.Msg.GetInterval())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.svc.SetRuntimeStatsInterval(ctx, interval); err != nil {
		return nil, err
	}
	return connect.NewResponse(&netmonv1.SetRuntimeStatsIntervalResponse{
		Interval: durationpb.New(interval),
	}), nil
}

func mapSeverity(severity model.Severity) netmonv1.Severity {
	switch severity {
	case model.SeverityCrit:
		return netmonv1.Severity_SEVERITY_CRIT
	case model.SeverityWarn:
		return netmonv1.Severity_SEVERITY_WARN
	case model.SeverityInfo:
		return netmonv1.Severity_SEVERITY_INFO
	case model.SeverityOK:
		return netmonv1.Severity_SEVERITY_OK
	default:
		return netmonv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func mapStatusView(status monitor.StatusView) *netmonv1.GetStatusResponse {
	checks := make([]*netmonv1.Check, 0, len(status.Checks))
	for _, check := range status.Checks {
		checks = append(checks, &netmonv1.Check{
			Name:     check.Label,
			Severity: mapSeverity(check.Severity),
			Summary:  check.Summary,
			Detail:   check.Detail,
		})
	}

	return &netmonv1.GetStatusResponse{
		OverallSeverity: mapSeverity(status.OverallSeverity),
		Summary:         status.Summary,
		PublicIpv4:      status.PublicIPv4,
		PublicIpv6:      status.PublicIPv6,
		Checks:          checks,
	}
}

func mapTaskEvent(event monitor.TaskEvent) *netmonv1.TaskEvent {
	out := &netmonv1.TaskEvent{
		Id:    event.ID,
		Kind:  mapTaskEventKind(event.Kind),
		Error: event.Error,
	}
	if !event.At.IsZero() {
		out.At = timestamppb.New(event.At)
	}
	if event.Delay != 0 {
		out.Delay = durationpb.New(event.Delay)
	}
	if event.Duration != 0 {
		out.Duration = durationpb.New(event.Duration)
	}
	return out
}

func mapStatsSnapshot(snapshot stats.Snapshot) *netmonv1.GetStatsResponse {
	collectors := make(map[string]*netmonv1.CollectorCounters, len(snapshot.Collectors))
	for name, counters := range snapshot.Collectors {
		collectors[name] = &netmonv1.CollectorCounters{
			Started:  counters.Started,
			Finished: counters.Finished,
			Failed:   counters.Failed,
		}
	}

	tasksByID := make(map[string]*netmonv1.TaskCounters, len(snapshot.TasksByID))
	for id, counters := range snapshot.TasksByID {
		tasksByID[id] = mapTaskCounters(counters)
	}

	probes := make(map[string]*netmonv1.OutcomeCounters, len(snapshot.Probes))
	for key, counters := range snapshot.Probes {
		probes[key] = &netmonv1.OutcomeCounters{
			Total:   counters.Total,
			Success: counters.Success,
			Failure: counters.Failure,
		}
	}

	return &netmonv1.GetStatsResponse{
		Events: &netmonv1.EventCounters{
			Link:  snapshot.Events.Link,
			Addr:  snapshot.Events.Addr,
			Route: snapshot.Events.Route,
		},
		Collectors:    collectors,
		CollectorRuns: maps.Clone(snapshot.CollectorRuns),
		Tasks:         mapTaskCounters(snapshot.Tasks),
		TasksById:     tasksByID,
		Probes:        probes,
		Checks: &netmonv1.CheckCounters{
			Evaluations: snapshot.Checks.Evaluations,
			Changed:     snapshot.Checks.Changed,
			Passed:      snapshot.Checks.Passed,
			Failed:      snapshot.Checks.Failed,
		},
		Notifications: &netmonv1.NotificationCounters{
			Sent:    snapshot.Notifications.Sent,
			Skipped: snapshot.Notifications.Skipped,
			Failed:  snapshot.Notifications.Failed,
		},
		Traces: &netmonv1.TraceCounters{
			Started:   snapshot.Traces.Started,
			Completed: snapshot.Traces.Completed,
			Failed:    snapshot.Traces.Failed,
		},
	}
}

func mapTaskCounters(counters stats.TaskCounters) *netmonv1.TaskCounters {
	return &netmonv1.TaskCounters{
		Scheduled:   counters.Scheduled,
		Rescheduled: counters.Rescheduled,
		Executing:   counters.Executing,
		Executed:    counters.Executed,
		Cancelled:   counters.Cancelled,
		Failed:      counters.Failed,
	}
}

func mapTraceEvent(event trace.Event) *netmonv1.TraceEvent {
	out := &netmonv1.TraceEvent{
		TraceId: event.TraceID,
		Kind:    event.Kind,
		Message: event.Message,
		Fields:  maps.Clone(event.Fields),
	}
	if !event.At.IsZero() {
		out.At = timestamppb.New(event.At)
	}
	return out
}

func mapTaskEventKind(kind monitor.TaskEventKind) netmonv1.TaskEventKind {
	switch kind {
	case monitor.TaskEventScheduled:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_SCHEDULED
	case monitor.TaskEventRescheduled:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_RESCHEDULED
	case monitor.TaskEventExecuting:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_EXECUTING
	case monitor.TaskEventExecuted:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_EXECUTED
	case monitor.TaskEventCancelled:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_CANCELLED
	case monitor.TaskEventFailed:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_FAILED
	default:
		return netmonv1.TaskEventKind_TASK_EVENT_KIND_UNSPECIFIED
	}
}

func mapRefreshScope(scope netmonv1.RefreshScope) (monitor.RefreshScope, error) {
	switch scope {
	case netmonv1.RefreshScope_REFRESH_SCOPE_UNSPECIFIED, netmonv1.RefreshScope_REFRESH_SCOPE_ALL:
		return monitor.RefreshScopeAll, nil
	case netmonv1.RefreshScope_REFRESH_SCOPE_INTERFACE:
		return monitor.RefreshScopeInterface, nil
	case netmonv1.RefreshScope_REFRESH_SCOPE_LISTENERS:
		return monitor.RefreshScopeListeners, nil
	case netmonv1.RefreshScope_REFRESH_SCOPE_UPSTREAM:
		return monitor.RefreshScopeUpstream, nil
	default:
		return 0, fmt.Errorf("unknown refresh scope: %s", scope.String())
	}
}

func mapSocketProbe(probe model.SocketProbe) *netmonv1.ListenerBinding {
	addresses := append([]string{}, probe.Loopback...)
	addresses = append(addresses, probe.NonLoopback...)
	return &netmonv1.ListenerBinding{
		Any:          probe.HasLoopback() || probe.HasNonLoopback(),
		Ipv4:         hasProbeFamily(probe, 4),
		Ipv6:         hasProbeFamily(probe, 6),
		LoopbackOnly: probe.HasLoopback() && !probe.HasNonLoopback(),
		Addresses:    addresses,
	}
}

func mapDNSProbe(result model.DNSProbeResult) *netmonv1.DnsProbeResult {
	out := &netmonv1.DnsProbeResult{
		Name:   result.Name,
		Target: result.Target,
		Status: result.Status.String(),
		Detail: result.Detail,
	}
	if result.Latency != 0 {
		out.Latency = durationpb.New(result.Latency)
	}
	return out
}

func mapPublicIPObservation(observation model.PublicIPObservation) *netmonv1.PublicIPObservation {
	out := &netmonv1.PublicIPObservation{
		Provider: observation.Provider,
		Target:   observation.Target,
		Ip:       observation.IP,
		Detail:   observation.Detail,
	}
	if observation.Latency != 0 {
		out.Latency = durationpb.New(observation.Latency)
	}
	return out
}

func mapDNSSECProbeResult(result model.DNSSECProbeResult) *netmonv1.DnssecProbeResult {
	return &netmonv1.DnssecProbeResult{
		Positive: mapDNSSECProbeAttempt(result.Positive),
		Negative: mapDNSSECProbeAttempt(result.Negative),
	}
}

func mapDNSSECProbeAttempt(attempt model.DNSSECProbeAttempt) *netmonv1.DnssecProbeAttempt {
	out := &netmonv1.DnssecProbeAttempt{
		Name:   attempt.Name,
		Target: attempt.Target,
		Status: attempt.Status.String(),
		Rcode:  attempt.Rcode,
		Ad:     attempt.AD,
		Detail: attempt.Detail,
	}
	if attempt.Latency != 0 {
		out.Latency = durationpb.New(attempt.Latency)
	}
	return out
}

func hasProbeFamily(probe model.SocketProbe, family int) bool {
	combined := append([]string{}, probe.Loopback...)
	combined = append(combined, probe.NonLoopback...)
	return probeHasFamily(combined, family)
}

func parseProtoDuration(value *durationpb.Duration) (time.Duration, error) {
	if value == nil {
		return 0, fmt.Errorf("interval is required")
	}
	if err := value.CheckValid(); err != nil {
		return 0, err
	}
	return value.AsDuration(), nil
}
