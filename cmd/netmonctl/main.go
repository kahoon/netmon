package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/rpc"
	netmonv1 "github.com/kahoon/netmon/proto/netmon/v1"
	netmonv1connect "github.com/kahoon/netmon/proto/netmon/v1/netmonv1connect"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	forever        = 0
	requestTimeout = 5 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	command := os.Args[1]
	if command == "-h" || command == "--help" || command == "help" {
		usageFor(argsAfterHelp(os.Args[2:]))
		return
	}

	spec, ok := commandRegistry[command]
	if !ok {
		log.Fatalf("unknown command %q", command)
	}

	spec.run(spec, os.Args[2:])
}

func runStatus(spec commandSpec, args []string) {
	cmd := newCommandContext(spec, args)
	defer cmd.cancel()

	resp, err := cmd.client.GetStatus(cmd.ctx, connect.NewRequest(&netmonv1.GetStatusRequest{}))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Status:     %s\n", formatSeverity(resp.Msg.GetOverallSeverity()))
	fmt.Printf("Summary:    %s\n", defaultString(resp.Msg.GetSummary(), "healthy"))
	if publicIPv4 := resp.Msg.GetPublicIpv4(); publicIPv4 != "" {
		fmt.Printf("Public IPv4: %s\n", publicIPv4)
	}
	if publicIPv6 := resp.Msg.GetPublicIpv6(); publicIPv6 != "" {
		fmt.Printf("Public IPv6: %s\n", publicIPv6)
	}

	issues := failingChecks(resp.Msg.GetChecks())
	if len(issues) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("Issues:")
	for _, check := range issues {
		fmt.Printf("- %s: %s\n", check.GetName(), defaultString(check.GetSummary(), "unhealthy"))
	}
}

func runWatch(spec commandSpec, args []string) {
	cmd := newCommandContextWithTimeout(spec, args, forever)
	defer cmd.cancel()

	subject := "status"
	switch rest := cmd.fs.Args(); len(rest) {
	case 0:
	case 1:
		subject = strings.ToLower(strings.TrimSpace(rest[0]))
	default:
		cmd.fs.Usage()
		os.Exit(2)
	}

	switch subject {
	case "status":
		stream, err := cmd.client.WatchStatus(cmd.ctx, connect.NewRequest(&netmonv1.WatchStatusRequest{}))
		if err != nil {
			log.Fatal(err)
		}
		defer stream.Close()

		for stream.Receive() {
			printWatchStatus(stream.Msg().GetStatus())
		}
		if err := stream.Err(); err != nil && !isCanceledError(err) {
			log.Fatal(err)
		}
	case "tasks":
		stream, err := cmd.client.WatchTasks(cmd.ctx, connect.NewRequest(&netmonv1.WatchTasksRequest{}))
		if err != nil {
			log.Fatal(err)
		}
		defer stream.Close()

		for stream.Receive() {
			printTaskEvent(stream.Msg().GetEvent())
		}
		if err := stream.Err(); err != nil && !isCanceledError(err) {
			log.Fatal(err)
		}
	case "checks":
		stream, err := cmd.client.WatchChecks(cmd.ctx, connect.NewRequest(&netmonv1.WatchChecksRequest{}))
		if err != nil {
			log.Fatal(err)
		}
		defer stream.Close()

		for stream.Receive() {
			printCheckEvent(stream.Msg().GetEvent())
		}
		if err := stream.Err(); err != nil && !isCanceledError(err) {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown watch subject %q", subject)
	}
}

func runTrace(spec commandSpec, args []string) {
	var noTraceID bool
	var scopeName string
	cmd := newCommandContextWithTimeout(spec, args, forever, func(fs *flag.FlagSet) {
		fs.BoolVar(&noTraceID, "no-trace-id", false, "Don't include a trace ID in emitted events (for testing)")
		fs.StringVar(&scopeName, "scope", "all", "Trace scope: all, interface, listeners, upstream, unbound, pihole")
	})
	defer cmd.cancel()

	scope, err := parseRefreshScope(scopeName)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := cmd.client.Trace(cmd.ctx, connect.NewRequest(&netmonv1.TraceRequest{Scope: scope}))
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()

	for stream.Receive() {
		printTraceEvent(stream.Msg().GetEvent(), noTraceID)
	}
	if err := stream.Err(); err != nil && !isCanceledError(err) {
		log.Fatal(err)
	}
}

func runChecks(spec commandSpec, args []string) {
	var showAll bool
	cmd := newCommandContext(spec, args, func(fs *flag.FlagSet) {
		fs.BoolVar(&showAll, "all", false, "Show healthy checks too")
	})
	defer cmd.cancel()

	resp, err := cmd.client.GetStatus(cmd.ctx, connect.NewRequest(&netmonv1.GetStatusRequest{}))
	if err != nil {
		log.Fatal(err)
	}

	checks := resp.Msg.GetChecks()
	if !showAll {
		checks = failingChecks(checks)
	}

	if len(checks) == 0 {
		if showAll {
			fmt.Println("No checks returned.")
		} else {
			fmt.Println("No failing checks.")
		}
		return
	}

	for _, check := range checks {
		fmt.Printf("%-24s %-4s %s\n", check.GetName(), formatSeverity(check.GetSeverity()), defaultString(check.GetSummary(), "healthy"))
		if detail := check.GetDetail(); detail != "" {
			fmt.Printf("  %s\n", detail)
		}
	}
}

func runState(spec commandSpec, args []string) {
	var jsonOutput bool
	cmd := newCommandContext(spec, args, func(fs *flag.FlagSet) {
		fs.BoolVar(&jsonOutput, "json", false, "Render raw JSON")
	})
	defer cmd.cancel()

	resp, err := cmd.client.GetState(cmd.ctx, connect.NewRequest(&netmonv1.GetStateRequest{}))
	if err != nil {
		log.Fatal(err)
	}

	if !jsonOutput {
		printState(resp.Msg)
		return
	}

	data, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(resp.Msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))
}

func runStats(spec commandSpec, args []string) {
	var jsonOutput bool
	cmd := newCommandContext(spec, args, func(fs *flag.FlagSet) {
		fs.BoolVar(&jsonOutput, "json", false, "Render raw JSON")
	})
	defer cmd.cancel()

	resp, err := cmd.client.GetStats(cmd.ctx, connect.NewRequest(&netmonv1.GetStatsRequest{}))
	if err != nil {
		log.Fatal(err)
	}

	if !jsonOutput {
		printStats(resp.Msg)
		return
	}

	data, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(resp.Msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))
}

func runInfo(spec commandSpec, args []string) {
	cmd := newCommandContext(spec, args)
	defer cmd.cancel()

	resp, err := cmd.client.GetInfo(cmd.ctx, connect.NewRequest(&netmonv1.GetInfoRequest{}))
	if err != nil {
		log.Fatal(err)
	}

	startedAt := time.Unix(resp.Msg.GetStartedAtUnix(), 0).Local()
	fmt.Printf("Version:            %s\n", resp.Msg.GetVersion())
	fmt.Printf("Commit:             %s\n", resp.Msg.GetCommit())
	fmt.Printf("Build Time:         %s\n", resp.Msg.GetBuildTime())
	fmt.Printf("Started At:         %s\n", startedAt.Format(time.RFC3339))
	fmt.Printf("Uptime:             %s\n", formatDuration(time.Since(startedAt)))
	fmt.Printf("Interface:          %s\n", resp.Msg.GetMonitorInterface())
	fmt.Printf("Interface Poll:     %s\n", resp.Msg.GetInterfacePoll())
	fmt.Printf("Listener Poll:      %s\n", resp.Msg.GetListenerPoll())
	fmt.Printf("Upstream Poll:      %s\n", resp.Msg.GetUpstreamPoll())
	fmt.Printf("Unbound Poll:       %s\n", resp.Msg.GetUnboundPoll())
	fmt.Printf("Pi-hole Poll:       %s\n", resp.Msg.GetPiholePoll())
	fmt.Printf("Runtime Stats:      %s\n", resp.Msg.GetRuntimeStatsInterval())
	fmt.Printf("Notify Host:        %s\n", resp.Msg.GetNtfyHost())
	fmt.Printf("RPC Socket:         %s\n", cmd.socketPath)
}

func runRefresh(spec commandSpec, args []string) {
	var scopeName string
	cmd := newCommandContext(spec, args, func(fs *flag.FlagSet) {
		fs.StringVar(&scopeName, "scope", "all", "Refresh scope: all, interface, listeners, upstream, unbound, pihole")
	})
	defer cmd.cancel()

	scope, err := parseRefreshScope(scopeName)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := cmd.client.Refresh(cmd.ctx, connect.NewRequest(&netmonv1.RefreshRequest{Scope: scope})); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Triggered refresh: %s\n", canonicalRefreshScope(scope))
}

func runSet(spec commandSpec, args []string) {
	cmd := newCommandContext(spec, args)
	defer cmd.cancel()

	rest := cmd.fs.Args()
	if len(rest) != 2 {
		cmd.fs.Usage()
		os.Exit(2)
	}

	setting := strings.ToLower(strings.TrimSpace(rest[0]))
	switch setting {
	case "debug", "debug-logging":
		var enabled bool
		input := strings.ToLower(strings.TrimSpace(rest[1]))
		switch input {
		case "on", "true", "enabled", "enable":
			enabled = true
		case "off", "false", "disabled", "disable":
			enabled = false
		default:
			log.Fatalf("invalid value for debug setting: %q (use on/off)", rest[1])
		}
		_, err := cmd.client.SetDebug(cmd.ctx, connect.NewRequest(&netmonv1.SetDebugRequest{
			Debug: enabled,
		}))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s = %s\n", setting, input)
	case "runtime-stats-interval":
		interval, err := time.ParseDuration(rest[1])
		if err != nil {
			log.Fatalf("invalid duration %q: %v", rest[1], err)
		}

		resp, err := cmd.client.SetRuntimeStatsInterval(cmd.ctx, connect.NewRequest(&netmonv1.SetRuntimeStatsIntervalRequest{
			Interval: durationpb.New(interval),
		}))
		if err != nil {
			log.Fatal(err)
		}
		applied := resp.Msg.GetInterval().AsDuration()
		fmt.Printf("%s = %s\n", setting, applied)
	default:
		log.Fatalf("unknown setting %q", rest[0])
	}
}

type commandContext struct {
	fs         *flag.FlagSet
	socketPath string
	client     netmonv1connect.NetmonServiceClient
	ctx        context.Context
	cancel     context.CancelFunc
}

func newCommandContext(spec commandSpec, args []string, bind ...func(*flag.FlagSet)) commandContext {
	return newCommandContextWithTimeout(spec, args, requestTimeout, bind...)
}

func newCommandContextWithTimeout(spec commandSpec, args []string, timeout time.Duration, bind ...func(*flag.FlagSet)) commandContext {
	fs := flag.NewFlagSet(spec.name, flag.ExitOnError)
	socketPath := fs.String("socket", defaultSocketPath(), "Unix socket path")
	fs.Usage = func() { fmt.Fprint(os.Stderr, spec.help) }
	for _, b := range bind {
		b(fs)
	}
	fs.Parse(args)

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	ctx := baseCtx
	cancel := stop
	if timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(baseCtx, timeout)
		cancel = func() {
			timeoutCancel()
			stop()
		}
	}
	return commandContext{
		fs:         fs,
		socketPath: *socketPath,
		client:     rpc.NewClient(*socketPath),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func defaultSocketPath() string {
	value := strings.TrimSpace(os.Getenv("RPC_SOCKET_PATH"))
	if value == "" {
		return config.DefaultRPCSocketPath
	}
	return value
}

func parseRefreshScope(value string) (netmonv1.RefreshScope, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all":
		return netmonv1.RefreshScope_REFRESH_SCOPE_ALL, nil
	case "interface":
		return netmonv1.RefreshScope_REFRESH_SCOPE_INTERFACE, nil
	case "listeners":
		return netmonv1.RefreshScope_REFRESH_SCOPE_LISTENERS, nil
	case "upstream":
		return netmonv1.RefreshScope_REFRESH_SCOPE_UPSTREAM, nil
	case "unbound":
		return netmonv1.RefreshScope_REFRESH_SCOPE_UNBOUND, nil
	case "pihole":
		return netmonv1.RefreshScope_REFRESH_SCOPE_PIHOLE, nil
	default:
		return 0, fmt.Errorf("unknown refresh scope %q", value)
	}
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func canonicalRefreshScope(scope netmonv1.RefreshScope) string {
	switch scope {
	case netmonv1.RefreshScope_REFRESH_SCOPE_INTERFACE:
		return "interface"
	case netmonv1.RefreshScope_REFRESH_SCOPE_LISTENERS:
		return "listeners"
	case netmonv1.RefreshScope_REFRESH_SCOPE_UPSTREAM:
		return "upstream"
	case netmonv1.RefreshScope_REFRESH_SCOPE_UNBOUND:
		return "unbound"
	case netmonv1.RefreshScope_REFRESH_SCOPE_PIHOLE:
		return "pihole"
	default:
		return "all"
	}
}

func formatSeverity(severity netmonv1.Severity) string {
	switch severity {
	case netmonv1.Severity_SEVERITY_OK:
		return "OK"
	case netmonv1.Severity_SEVERITY_INFO:
		return "INFO"
	case netmonv1.Severity_SEVERITY_WARN:
		return "WARN"
	case netmonv1.Severity_SEVERITY_CRIT:
		return "CRIT"
	default:
		return "UNKNOWN"
	}
}

func failingChecks(checks []*netmonv1.Check) []*netmonv1.Check {
	out := make([]*netmonv1.Check, 0, len(checks))
	for _, check := range checks {
		if check.GetSeverity() == netmonv1.Severity_SEVERITY_OK {
			continue
		}
		out = append(out, check)
	}
	return out
}

func printState(resp *netmonv1.GetStateResponse) {
	iface := resp.GetInterface()
	fmt.Println("Interface")
	fmt.Printf("  Name:        %s\n", defaultString(iface.GetName(), "(unknown)"))
	fmt.Printf("  Link Index:  %d\n", iface.GetLinkIndex())
	fmt.Printf("  Link Up:     %t\n", iface.GetLinkUp())
	fmt.Printf("  Oper State:  %s\n", defaultString(iface.GetOperState(), "(unknown)"))
	fmt.Printf("  ULA:         %s\n", joinOrNone(iface.GetUla()))
	fmt.Printf("  GUA:         %s\n", joinOrNone(iface.GetGua()))
	fmt.Printf("  Usable GUA:  %s\n", joinOrNone(iface.GetUsableGua()))

	fmt.Println()
	fmt.Println("Listeners")
	printListenerBinding("53/tcp", resp.GetListeners().GetDns53Tcp())
	printListenerBinding("53/udp", resp.GetListeners().GetDns53Udp())
	printListenerBinding("5335/tcp", resp.GetListeners().GetResolver5335Tcp())
	printListenerBinding("5335/udp", resp.GetListeners().GetResolver5335Udp())

	fmt.Println()
	fmt.Println("Upstream")
	printDNSProbe("Root DNS IPv4", resp.GetUpstream().GetRootV4())
	printDNSProbe("Root DNS IPv6", resp.GetUpstream().GetRootV6())
	printDNSProbe("Recursive DNS IPv4", resp.GetUpstream().GetRecursiveV4())
	printDNSProbe("Recursive DNS IPv6", resp.GetUpstream().GetRecursiveV6())
	printPublicIPObservation("Public IPv4", resp.GetUpstream().GetPublicIpv4())
	printPublicIPObservation("Public IPv6", resp.GetUpstream().GetPublicIpv6())

	fmt.Println()
	fmt.Println("Unbound")
	printDNSSECProbe("DNSSEC Positive", resp.GetUnbound().GetDnssec().GetPositive())
	printDNSSECProbe("DNSSEC Negative", resp.GetUnbound().GetDnssec().GetNegative())

	fmt.Println()
	fmt.Println("Pi-hole")
	printDNSProbe("DNS IPv4", resp.GetPihole().GetDnsV4())
	printDNSProbe("DNS IPv6", resp.GetPihole().GetDnsV6())
	printPiHoleStatus(resp.GetPihole().GetStatus())
	printPiHoleUpstreams(resp.GetPihole().GetUpstreams())
	printPiHoleGravity(resp.GetPihole().GetGravity())
	printPiHoleCounters(resp.GetPihole().GetCounters())
	printDNSLatencyWindow("Latency IPv4", resp.GetPihole().GetLatencyIpv4())
	printDNSLatencyWindow("Latency IPv6", resp.GetPihole().GetLatencyIpv6())
}

func printStats(resp *netmonv1.GetStatsResponse) {
	if events := resp.GetEvents(); events != nil {
		fmt.Println("Events")
		fmt.Printf("  link:  %d\n", events.GetLink())
		fmt.Printf("  addr:  %d\n", events.GetAddr())
		fmt.Printf("  route: %d\n", events.GetRoute())
		fmt.Println()
	}

	if checks := resp.GetChecks(); checks != nil {
		fmt.Println("Checks")
		fmt.Printf("  evaluations: %d\n", checks.GetEvaluations())
		fmt.Printf("  changed:     %d\n", checks.GetChanged())
		fmt.Printf("  passed:      %d\n", checks.GetPassed())
		fmt.Printf("  failed:      %d\n", checks.GetFailed())
		fmt.Println()
	}

	if notifications := resp.GetNotifications(); notifications != nil {
		fmt.Println("Notifications")
		fmt.Printf("  sent:    %d\n", notifications.GetSent())
		fmt.Printf("  skipped: %d\n", notifications.GetSkipped())
		fmt.Printf("  failed:  %d\n", notifications.GetFailed())
		fmt.Println()
	}

	if traces := resp.GetTraces(); traces != nil {
		fmt.Println("Traces")
		fmt.Printf("  started:   %d\n", traces.GetStarted())
		fmt.Printf("  completed: %d\n", traces.GetCompleted())
		fmt.Printf("  failed:    %d\n", traces.GetFailed())
		fmt.Println()
	}

	if tasks := resp.GetTasks(); tasks != nil {
		fmt.Println("Tasks")
		fmt.Printf("  scheduled:   %d\n", tasks.GetScheduled())
		fmt.Printf("  rescheduled: %d\n", tasks.GetRescheduled())
		fmt.Printf("  executing:   %d\n", tasks.GetExecuting())
		fmt.Printf("  executed:    %d\n", tasks.GetExecuted())
		fmt.Printf("  cancelled:   %d\n", tasks.GetCancelled())
		fmt.Printf("  failed:      %d\n", tasks.GetFailed())
		fmt.Println()
	}

	if collectors := resp.GetCollectors(); len(collectors) > 0 {
		fmt.Println("Collectors")
		names := sortedKeys(collectors)
		for _, name := range names {
			counters := collectors[name]
			fmt.Printf("  %s: started=%d finished=%d failed=%d\n", name, counters.GetStarted(), counters.GetFinished(), counters.GetFailed())
		}
		fmt.Println()
	}

	if reasons := resp.GetCollectorRuns(); len(reasons) > 0 {
		fmt.Println("Collector Reasons")
		names := sortedKeys(reasons)
		for _, name := range names {
			fmt.Printf("  %s: %d\n", name, reasons[name])
		}
		fmt.Println()
	}

	if probes := resp.GetProbes(); len(probes) > 0 {
		fmt.Println("Probes")
		names := sortedKeys(probes)
		for _, name := range names {
			counters := probes[name]
			fmt.Printf("  %s: total=%d success=%d failure=%d\n", name, counters.GetTotal(), counters.GetSuccess(), counters.GetFailure())
		}
		fmt.Println()
	}

	if tasksByID := resp.GetTasksById(); len(tasksByID) > 0 {
		fmt.Println("Tasks By ID")
		names := sortedKeys(tasksByID)
		for _, name := range names {
			counters := tasksByID[name]
			fmt.Printf("  %s: scheduled=%d rescheduled=%d executing=%d executed=%d cancelled=%d failed=%d\n",
				name,
				counters.GetScheduled(),
				counters.GetRescheduled(),
				counters.GetExecuting(),
				counters.GetExecuted(),
				counters.GetCancelled(),
				counters.GetFailed(),
			)
		}
	}
}

func printWatchStatus(resp *netmonv1.GetStatusResponse) {
	timestamp := time.Now().Local().Format(time.RFC3339)
	fmt.Printf("[%s] %-4s %s\n", timestamp, formatSeverity(resp.GetOverallSeverity()), defaultString(resp.GetSummary(), "healthy"))
	if publicIPv4 := resp.GetPublicIpv4(); publicIPv4 != "" {
		fmt.Printf("  Public IPv4: %s\n", publicIPv4)
	}
	if publicIPv6 := resp.GetPublicIpv6(); publicIPv6 != "" {
		fmt.Printf("  Public IPv6: %s\n", publicIPv6)
	}
	for _, check := range failingChecks(resp.GetChecks()) {
		fmt.Printf("  - %s: %s\n", check.GetName(), defaultString(check.GetSummary(), "unhealthy"))
	}
}

func printTaskEvent(event *netmonv1.TaskEvent) {
	if event == nil {
		return
	}

	timestamp := time.Now().Local()
	if at := event.GetAt(); at != nil {
		timestamp = at.AsTime().Local()
	}

	line := fmt.Sprintf("[%s] %-11s %s", timestamp.Format(time.RFC3339), formatTaskEventKind(event.GetKind()), event.GetId())
	if delay := event.GetDelay(); delay != nil {
		line += fmt.Sprintf(" delay=%s", delay.AsDuration())
	}
	if duration := event.GetDuration(); duration != nil {
		line += fmt.Sprintf(" duration=%s", duration.AsDuration())
	}
	if detail := event.GetError(); detail != "" {
		line += fmt.Sprintf(" error=%s", detail)
	}
	fmt.Println(line)
}

func printCheckEvent(event *netmonv1.CheckEvent) {
	if event == nil {
		return
	}

	timestamp := time.Now().Local()
	if at := event.GetAt(); at != nil {
		timestamp = at.AsTime().Local()
	}

	label := defaultString(event.GetLabel(), event.GetKey())
	line := fmt.Sprintf(
		"[%s] %-20s %s -> %s  %s",
		timestamp.Format(time.RFC3339),
		defaultString(event.GetKey(), label),
		formatSeverity(event.GetPreviousSeverity()),
		formatSeverity(event.GetCurrentSeverity()),
		defaultString(event.GetCurrentSummary(), "healthy"),
	)
	fmt.Println(line)
	if detail := event.GetCurrentDetail(); detail != "" {
		fmt.Printf("  %s\n", detail)
	}
}

func printTraceEvent(event *netmonv1.TraceEvent, noTraceID bool) {
	if event == nil {
		return
	}

	timestamp := time.Now().Local()
	if at := event.GetAt(); at != nil {
		timestamp = at.AsTime().Local()
	}

	line := fmt.Sprintf("[%s] %-20s %s", timestamp.Format(time.RFC3339), event.GetKind(), event.GetMessage())
	if traceID := event.GetTraceId(); traceID != "" && !noTraceID {
		line += " trace_id=" + traceID
	}
	fields := event.GetFields()
	if len(fields) > 0 {
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s=%s", key, fields[key]))
		}
		line += " " + strings.Join(parts, " ")
	}
	fmt.Println(line)
}

func printListenerBinding(label string, binding *netmonv1.ListenerBinding) {
	fmt.Printf("  %-12s any=%t ipv4=%t ipv6=%t loopback_only=%t\n", label, binding.GetAny(), binding.GetIpv4(), binding.GetIpv6(), binding.GetLoopbackOnly())
	fmt.Printf("  %-12s addresses=%s\n", "", joinOrNone(binding.GetAddresses()))
}

func printDNSProbe(label string, probe *netmonv1.DnsProbeResult) {
	fmt.Printf("  %-19s %s\n", label+":", formatProbeStatus(probe.GetStatus()))
	if name := probe.GetName(); name != "" {
		fmt.Printf("  %-19s %s\n", "", name)
	}
	if target := probe.GetTarget(); target != "" {
		fmt.Printf("  %-19s %s\n", "", target)
	}
	if latency := probe.GetLatency(); latency != nil {
		fmt.Printf("  %-19s latency=%s\n", "", latency.AsDuration())
	}
	if detail := probe.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	cloned := append([]string{}, values...)
	sort.Strings(cloned)
	return strings.Join(cloned, ", ")
}

func printPublicIPObservation(label string, observation *netmonv1.PublicIPObservation) {
	fmt.Printf("  %-19s %s\n", label+":", defaultString(observation.GetIp(), "(unknown)"))
	if provider := observation.GetProvider(); provider != "" {
		fmt.Printf("  %-19s provider=%s\n", "", provider)
	}
	if target := observation.GetTarget(); target != "" {
		fmt.Printf("  %-19s target=%s\n", "", target)
	}
	if latency := observation.GetLatency(); latency != nil {
		fmt.Printf("  %-19s latency=%s\n", "", latency.AsDuration())
	}
	if detail := observation.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
}

func printDNSSECProbe(label string, probe *netmonv1.DnssecProbeAttempt) {
	fmt.Printf("  %-19s %s\n", label+":", formatProbeStatus(probe.GetStatus()))
	if name := probe.GetName(); name != "" {
		fmt.Printf("  %-19s %s\n", "", name)
	}
	if target := probe.GetTarget(); target != "" {
		fmt.Printf("  %-19s target=%s\n", "", target)
	}
	if rcode := probe.GetRcode(); rcode != "" {
		fmt.Printf("  %-19s rcode=%s ad=%t\n", "", rcode, probe.GetAd())
	}
	if latency := probe.GetLatency(); latency != nil {
		fmt.Printf("  %-19s latency=%s\n", "", latency.AsDuration())
	}
	if detail := probe.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
}

func printPiHoleStatus(status *netmonv1.PiHoleStatus) {
	fmt.Printf("  %-19s %s\n", "Blocking:", defaultString(status.GetBlocking(), "(unknown)"))
	if detail := status.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
	if version := joinNamedValues(
		"core", status.GetCoreVersion(),
		"web", status.GetWebVersion(),
		"ftl", status.GetFtlVersion(),
	); version != "" {
		fmt.Printf("  %-19s %s\n", "Versions:", version)
	}
}

func printPiHoleUpstreams(upstreams *netmonv1.PiHoleUpstreams) {
	fmt.Printf("  %-19s %s\n", "Upstreams:", joinOrNone(upstreams.GetServers()))
	fmt.Printf("  %-19s matches_expected=%t\n", "", upstreams.GetMatchesExpected())
	if detail := upstreams.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
}

func printPiHoleGravity(gravity *netmonv1.PiHoleGravity) {
	lastUpdated := "(unknown)"
	if ts := gravity.GetLastUpdated(); ts != nil {
		lastUpdated = ts.AsTime().Local().Format(time.RFC3339)
	}
	fmt.Printf("  %-19s %s\n", "Gravity Updated:", lastUpdated)
	fmt.Printf("  %-19s domains_blocked=%d stale=%t\n", "", gravity.GetDomainsBlocked(), gravity.GetStale())
	if detail := gravity.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
}

func printPiHoleCounters(counters *netmonv1.PiHoleCounters) {
	fmt.Printf("  %-19s total=%d blocked=%d cache_hits=%d forwarded=%d clients_active=%d\n",
		"Counters:",
		counters.GetQueriesTotal(),
		counters.GetQueriesBlocked(),
		counters.GetCacheHits(),
		counters.GetForwarded(),
		counters.GetClientsActive(),
	)
	if detail := counters.GetDetail(); detail != "" {
		fmt.Printf("  %-19s %s\n", "", detail)
	}
}

func printDNSLatencyWindow(label string, window *netmonv1.DnsLatencyWindow) {
	fmt.Printf("  %-19s trend=%s samples=%d\n", label+":", defaultString(window.GetTrend(), "unknown"), window.GetSamples())
	var parts []string
	if last := window.GetLast(); last != nil {
		parts = append(parts, "last="+last.AsDuration().String())
	}
	if average := window.GetAverage(); average != nil {
		parts = append(parts, "avg="+average.AsDuration().String())
	}
	if max := window.GetMax(); max != nil {
		parts = append(parts, "max="+max.AsDuration().String())
	}
	if len(parts) > 0 {
		fmt.Printf("  %-19s %s\n", "", strings.Join(parts, " "))
	}
}

func joinNamedValues(values ...string) string {
	if len(values)%2 != 0 {
		return ""
	}
	parts := make([]string, 0, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		name := strings.TrimSpace(values[i])
		value := strings.TrimSpace(values[i+1])
		if value == "" {
			continue
		}
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, " ")
}

func formatProbeStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "UNKNOWN"
	}
	status = strings.ReplaceAll(status, "_", " ")
	return strings.ToUpper(status)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return d.Truncate(time.Second).String()
}

func formatTaskEventKind(kind netmonv1.TaskEventKind) string {
	switch kind {
	case netmonv1.TaskEventKind_TASK_EVENT_KIND_SCHEDULED:
		return "scheduled"
	case netmonv1.TaskEventKind_TASK_EVENT_KIND_RESCHEDULED:
		return "rescheduled"
	case netmonv1.TaskEventKind_TASK_EVENT_KIND_EXECUTING:
		return "executing"
	case netmonv1.TaskEventKind_TASK_EVENT_KIND_EXECUTED:
		return "executed"
	case netmonv1.TaskEventKind_TASK_EVENT_KIND_CANCELLED:
		return "cancelled"
	case netmonv1.TaskEventKind_TASK_EVENT_KIND_FAILED:
		return "failed"
	default:
		return "unknown"
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func isCanceledError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	var connectErr *connect.Error
	return errors.As(err, &connectErr) && connectErr.Code() == connect.CodeCanceled
}
