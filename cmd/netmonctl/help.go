package main

import (
	"fmt"
	"io"
	"os"
)

type commandSpec struct {
	name    string
	summary string
	help    string
	run     func(commandSpec, []string)
}

var commandOrder = []string{
	"top",
	"status",
	"trace",
	"watch",
	"checks",
	"state",
	"stats",
	"info",
	"refresh",
	"set",
}

var commandRegistry = map[string]commandSpec{
	"top": {
		name:    "top",
		summary: "Live dashboard: checks, Pi-hole, and Tailscale at a glance.",
		help: `Live full-screen dashboard showing checks, Pi-hole, and Tailscale state.

Refreshes the check panel via a live stream. Fetches detail state every 30s.

Keys:
  r   Trigger an immediate full refresh
  q   Quit

Usage:
  netmonctl top [-socket path]

Examples:
  netmonctl top
`,
		run: runTop,
	},
	"status": {
		name:    "status",
		summary: "Show the current overall health summary and observed public IPs.",
		help: `Show the current overall health summary.

Usage:
  netmonctl status [-socket path]

Examples:
  netmonctl status
  netmonctl status -socket /run/netmon/netmond.sock
`,
		run: runStatus,
	},
	"watch": {
		name:    "watch",
		summary: "Stream live status, check, or task updates from the running daemon.",
		help: `Stream live updates from the running daemon.

Subjects:
  status   Print the current health view immediately, then stream changes.
  tasks    Stream pending task telemetry events from the running daemon.
  checks   Stream recent and live individual check transitions.

Usage:
  netmonctl watch [status|tasks|checks] [-socket path]

Examples:
  netmonctl watch
  netmonctl watch status
  netmonctl watch tasks
  netmonctl watch checks
`,
		run: runWatch,
	},
	"trace": {
		name:    "trace",
		summary: "Run a traced refresh and stream the causal path end to end.",
		help: `Run a traced refresh and stream the causal path end to end.

Scopes:
  all         Trace interface, listeners, upstream, unbound, pihole, and tailscale refresh work.
  interface   Trace only interface collection.
  listeners   Trace only listener collection.
  upstream    Trace only upstream probes.
  unbound     Trace only unbound probes.
  pihole      Trace only Pi-hole collection.
  tailscale   Trace only Tailscale collection.

Usage:
  netmonctl trace [-socket path] [-no-trace-id] [-scope all|interface|listeners|upstream|unbound|pihole|tailscale]

Examples:
  netmonctl trace
  netmonctl trace -scope upstream
  netmonctl trace -scope unbound
  netmonctl trace -scope pihole
  netmonctl trace -scope tailscale
`,
		run: runTrace,
	},
	"checks": {
		name:    "checks",
		summary: "List current health checks.",
		help: `List current health checks.

By default, only non-OK checks are shown. Use -all to include healthy checks.

Usage:
  netmonctl checks [-socket path] [-all]

Examples:
  netmonctl checks
  netmonctl checks -all
`,
		run: runChecks,
	},
	"state": {
		name:    "state",
		summary: "Show the daemon's current collected state.",
		help: `Show the daemon's current collected state.

The default output is a readable summary. Use -json for the raw RPC response.

Usage:
  netmonctl state [-socket path] [-json]

Examples:
  netmonctl state
  netmonctl state -json
`,
		run: runState,
	},
	"info": {
		name:    "info",
		summary: "Show daemon build and runtime metadata.",
		help: `Show daemon build and runtime metadata.

Usage:
  netmonctl info [-socket path]

Examples:
  netmonctl info
`,
		run: runInfo,
	},
	"stats": {
		name:    "stats",
		summary: "Show lifetime daemon counters.",
		help: `Show lifetime daemon counters.

The default output is a readable summary. Use -json for the raw RPC response.

Usage:
  netmonctl stats [-socket path] [-json]

Examples:
  netmonctl stats
  netmonctl stats -json
`,
		run: runStats,
	},
	"refresh": {
		name:    "refresh",
		summary: "Trigger an immediate refresh in the running daemon.",
		help: `Trigger an immediate refresh in the running daemon.

Scopes:
  all         Refresh interface, listeners, upstream, unbound, pihole, and tailscale state.
  interface   Refresh only interface state.
  listeners   Refresh only listener state.
  upstream    Refresh only upstream probes.
  unbound     Refresh only unbound probes.
  pihole      Refresh only Pi-hole state.
  tailscale   Refresh only Tailscale state.

Usage:
  netmonctl refresh [-socket path] [-scope all|interface|listeners|upstream|unbound|pihole|tailscale]

Examples:
  netmonctl refresh
  netmonctl refresh -scope upstream
  netmonctl refresh -scope unbound
  netmonctl refresh -scope pihole
  netmonctl refresh -scope tailscale
`,
		run: runRefresh,
	},
	"set": {
		name:    "set",
		summary: "Change mutable runtime settings in the running daemon.",
		help: `Change mutable runtime settings in the running daemon.

Currently supported settings:
  debug-logging            Enable or disable debug logging.
                           Use "on" or "off" to set the value.
  runtime-stats-interval   Set the runtime stats logging interval.
                           Use 0 to disable the reporter.

Usage:
  netmonctl set [debug-logging <on/off>|runtime-stats-interval <duration>] [-socket path]

Examples:
  netmonctl set debug-logging on
  netmonctl set runtime-stats-interval 30m
  netmonctl set runtime-stats-interval 0
`,
		run: runSet,
	},
}

func usage() {
	writeUsage(os.Stderr)
}

func usageFor(command string) {
	if command == "" {
		usage()
		return
	}

	spec, ok := commandRegistry[command]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown help topic %q\n", command)
		os.Exit(2)
	}

	fmt.Fprint(os.Stderr, spec.help)
}

func commandUsageFunc(commandName string) func() {
	spec, ok := commandRegistry[commandName]
	return func() {
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown command %q\n", commandName)
			return
		}
		fmt.Fprint(os.Stderr, spec.help)
	}
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "netmonctl talks to netmond over a Unix domain socket.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  netmonctl <command> [flags]")
	fmt.Fprintln(w, "  netmonctl help [command]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, name := range commandOrder {
		spec := commandRegistry[name]
		fmt.Fprintf(w, "  %-8s %s\n", spec.name, spec.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global Notes:")
	fmt.Fprintln(w, "  All commands accept -socket to override the default socket path.")
	fmt.Fprintf(w, "  The default socket path is %s.\n", defaultSocketPath())
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  netmonctl status")
	fmt.Fprintln(w, "  netmonctl watch")
	fmt.Fprintln(w, "  netmonctl watch tasks")
	fmt.Fprintln(w, "  netmonctl watch checks")
	fmt.Fprintln(w, "  netmonctl checks -all")
	fmt.Fprintln(w, "  netmonctl state -json")
	fmt.Fprintln(w, "  netmonctl stats")
	fmt.Fprintln(w, "  netmonctl refresh -scope pihole")
	fmt.Fprintln(w, "  netmonctl refresh -scope unbound")
	fmt.Fprintln(w, "  netmonctl refresh -scope tailscale")
	fmt.Fprintln(w, "  netmonctl set runtime-stats-interval 30m")
	fmt.Fprintln(w, "  netmonctl help refresh")
}

func argsAfterHelp(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
