# netmon

`netmon` is a small Linux network monitor for a DNS appliance host.

It watches one interface with netlink, runs separate collectors for interface
state, listener state, upstream reachability, local Unbound validation, local
Pi-hole service/configuration state, and local Tailscale state, evaluates a fixed set of health
checks, sends an `ntfy` notification only when the check results change, and
exposes a local Connect RPC API over a Unix domain socket.

The current health model is intentionally narrow:

- the monitored interface must remain operational
- the expected IPv6 ULA must be present
- at least one usable IPv6 GUA must be present
- port `53` must be listening on non-loopback IPv4 and IPv6
- port `5335` must be listening on loopback only
- external DNS health must remain functional over IPv4 and IPv6
- local Unbound DNSSEC validation must behave correctly
- Pi-hole must answer DNS correctly over IPv4 and IPv6
- Pi-hole must remain enabled
- Pi-hole must forward only to local Unbound
- Pi-hole gravity must not become stale
- Tailscale must remain connected to the tailnet
- public IPv4 and public IPv6 changes are observed and reported as informational changes

This makes it much quieter than a raw address-change notifier. Temporary IPv6
churn is ignored unless it changes one of the checks above.

## What It Checks

For the monitored interface:

- operational state must remain `up`
- exact match for `EXPECTED_ULA`
- presence of at least one usable global IPv6 address
  - tentative and deprecated GUAs do not count

For listeners on the host:

- `53/tcp` must be reachable on a non-loopback IPv4 bind
- `53/tcp` must be reachable on a non-loopback IPv6 bind
- `53/udp` must be reachable on a non-loopback IPv4 bind
- `53/udp` must be reachable on a non-loopback IPv6 bind
- `5335/tcp` must be listening on loopback
- `5335/udp` must be listening on loopback
- any non-loopback listener on `5335` is treated as exposure and reported

For outbound reachability:

- an IPv4 UDP DNS query for `.` `NS` must succeed against one pinned root target
- an IPv6 UDP DNS query for `.` `NS` must succeed against one pinned root target
- recursive IPv4 resolution of the same pinned root hostnames must return the expected address
- recursive IPv6 resolution of the same pinned root hostnames must return the expected address
- the current public IPv4 is observed through a DNS-based provider chain
- the current public IPv6 is observed through a DNS-based provider chain

For local DNSSEC validation:

- a recursive `A` query for `internetsociety.org.` against local Unbound on `127.0.0.1:5335` must succeed with `AD=true`
- a recursive `A` query for `dnssec-failed.org.` against local Unbound on `127.0.0.1:5335` must fail with `SERVFAIL`

For local Pi-hole service and policy state:

- an IPv4 recursive query through Pi-hole on `127.0.0.1:53` must return the expected root-server address
- an IPv6 recursive query through Pi-hole on `::1:53` must return the expected root-server address
- Pi-hole blocking must remain enabled
- Pi-hole upstreams must remain pinned to local Unbound on `127.0.0.1#5335` and `::1#5335`
- Pi-hole gravity must not age past the configured freshness threshold

For local Tailscale state:

- `tailscale status --json` must report a running backend
- the node must remain authenticated
- at least one Tailscale address must be assigned
- the node must remain connected to the tailnet
- exit-node status and advertised routes are collected for operator visibility

## Alert Severity

- `CRIT`
  - monitored interface operational state is not `up`
  - expected ULA missing
  - `53/tcp` missing IPv4 or IPv6 coverage
  - `53/udp` missing IPv4 or IPv6 coverage
  - `5335/tcp` not listening on loopback
  - `5335/udp` not listening on loopback
  - Pi-hole DNS fails over IPv4
  - Pi-hole DNS fails over IPv6
  - Pi-hole blocking is disabled
  - Pi-hole upstreams do not match local Unbound
  - Tailscale is not connected
- `WARN`
  - no usable IPv6 GUA
  - external DNS is degraded on IPv4
  - external DNS is degraded on IPv6
  - DNSSEC validation is degraded
  - Pi-hole gravity is stale
  - `5335` is exposed on any non-loopback address
- `INFO`
  - recovery from a previous warning or critical condition

If both IPv4 DNS probes or both IPv6 DNS probes fail, the monitor reports `CRIT`.

Notifications include the reason for reconciliation, the state transition, and
only the changed non-OK checks. Recoveries are reported briefly, and successful
checks are omitted to keep mobile notifications short.

## Environment

Required:

- `NTFY_TOPIC`
  - `ntfy.sh` topic to publish notifications to

Recommended:

- `EXPECTED_ULA`
  - the exact static ULA you expect on the monitored interface
  - example: `fd8f:bd66:6363:1::15`

Optional:

- `MONITOR_IF`
  - interface name to monitor
  - default: `eno1`
- `NTFY_HOST`
  - notification host name
  - default: `ntfy.sh`
- `NTFY_RESOLVER`
  - DNS resolver used only for resolving the notification host
  - default: `9.9.9.9:53`
- `RPC_SOCKET_PATH`
  - Unix domain socket path for the local RPC API
  - default: `/run/netmon/netmond.sock`
- `DEBUG_EVENTS`
  - enables raw link, address, and route event logging
  - default: `false`
- `RUNTIME_STATS_INTERVAL`
  - interval for logging Go runtime stats
  - set to `0` to disable the reporter
  - default: `168h`
- `PIHOLE_PASSWORD`
  - bootstrap password used to obtain the short-lived Pi-hole API session token

Upstream probing is pinned in code:

- direct authority-style `NS .` probes go to `e.root-servers.net.` and `j.root-servers.net.`
- recursive health probes resolve those same root hostnames through public resolvers
- public IPv4 observation prefers OpenDNS and falls back to Google
- public IPv6 observation prefers Google and falls back to OpenDNS
- local DNSSEC validation probes target Unbound directly on `127.0.0.1:5335`
- local Pi-hole DNS probes target Pi-hole directly on `127.0.0.1:53` and `::1:53`
- Pi-hole policy/configuration state is read through the local Pi-hole v6 API
- Pi-hole gravity freshness currently uses a fixed `7d` threshold
- Tailscale state is read locally through `tailscale status --json` and `tailscale debug prefs`

If `EXPECTED_ULA` is unset, the ULA check is skipped.

## Build

Build on Linux:

```bash
go build ./cmd/netmond
```

Cross-compile from another machine:

```bash
GOOS=linux GOARCH=amd64 go build ./cmd/netmond
```

Convenience targets are also available:

```bash
make fmt
make generate
make test
make build
make build-linux
```

Builds stamp the binary with version metadata. Override it at build time if you
want a release identifier:

```bash
make VERSION=v0.1.0 build-linux
```

## Run

Example:

```bash
. /etc/default/netmon

./netmond
```

The process needs access to Linux netlink and `/proc/net/{tcp,tcp6,udp,udp6}`.
It is intended to run directly on the Debian host being monitored.

The local RPC API listens on:

```text
/run/netmon/netmond.sock
```

## CLI

The local CLI talks to `netmond` over the Unix domain socket. Typical commands:

```bash
netmonctl status
netmonctl trace
netmonctl watch status
netmonctl watch tasks
netmonctl watch checks
netmonctl checks
netmonctl checks --all
netmonctl state
netmonctl state --json
netmonctl info
netmonctl refresh --scope upstream
netmonctl refresh --scope pihole
netmonctl refresh --scope tailscale
netmonctl set debug-logging on
netmonctl set runtime-stats-interval 30m
netmonctl help refresh
```

Use `-socket` on any command if you want to override the default socket path.

## Trace

`netmonctl trace` runs a bounded traced refresh and streams the causal path end to end.

Unlike `watch`, which observes ongoing daemon state, `trace` causes a refresh itself and
then exits when that work completes. It is meant for answering questions like:

- which collectors ran
- which upstream probes succeeded or failed
- which local Pi-hole probes succeeded or failed
- whether Tailscale collection succeeded
- how checks changed
- whether a notification was sent or skipped
- how long the refresh took

Examples:

```bash
netmonctl trace
netmonctl trace -scope upstream
netmonctl trace -scope pihole
netmonctl trace -scope tailscale
```

Example output:

```text
[2026-04-17T16:02:11-04:00] trace_started        trace started scope=upstream
[2026-04-17T16:02:11-04:00] refresh_requested    refresh requested scope=upstream
[2026-04-17T16:02:11-04:00] collector_started    collector started collector=upstream reason=trace refresh
[2026-04-17T16:02:11-04:00] probe_result         probe result family=ipv4 latency=12.4ms probe_kind=root responder=192.203.230.10 status=ok target=e.root-servers.net.
[2026-04-17T16:02:11-04:00] probe_result         probe result family=ipv6 latency=15.1ms probe_kind=public_ip provider=Google status=ok ip=2607:f2c0:... target=2001:4860:4802:32::a
[2026-04-17T16:02:11-04:00] collector_finished   collector finished collector=upstream duration=58.3ms reason=trace refresh
[2026-04-17T16:02:11-04:00] collector_started    collector started collector=unbound reason=trace refresh
[2026-04-17T16:02:11-04:00] probe_result         probe result family=local latency=6.1ms probe_kind=dnssec_positive provider=unbound status=ok ad=true rcode=NOERROR target=127.0.0.1:5335
[2026-04-17T16:02:11-04:00] collector_finished   collector finished collector=unbound duration=7.4ms reason=trace refresh
[2026-04-17T16:02:11-04:00] checks_changed       checks evaluated changed=1 reason=trace refresh
[2026-04-17T16:02:11-04:00] notification_skipped notification skipped reason=no effective changes
[2026-04-17T16:02:11-04:00] trace_completed      trace completed duration=59.0ms scope=upstream
```

## Streaming and Live Observability

`netmon` exposes three live streaming views over its local Connect RPC API:

- `netmonctl watch status`
- `netmonctl watch tasks`
- `netmonctl watch checks`

They serve different purposes.

### `watch`: live health state

`netmonctl watch status` is the operator-facing stream.

It sends the current health view immediately when the client connects, then
pushes a new update only when the effective status changes. That means it is
quiet on a stable system and only speaks when something meaningful happens:

- overall severity changes
- one or more checks change
- the health summary changes
- the observed public IPv4 or public IPv6 changes

Example:

```text
[2026-04-15T20:14:03-04:00] OK   healthy
[2026-04-15T21:03:18-04:00] WARN external DNS over IPv6 failing
  - external DNS IPv6: external DNS over IPv6 failing
[2026-04-15T21:04:02-04:00] OK   healthy
```

This stream is intentionally state-oriented rather than event-oriented. It does
not replay every refresh tick or every netlink event. Instead, it answers the
question:

> “What changed in the effective health of the appliance?”

### `watch tasks`: live scheduler telemetry

`netmonctl watch tasks` is the implementation-facing stream.

It exposes the [`pending`](https://github.com/kahoon/pending) scheduler
lifecycle through the daemon’s local API. `pending` is a sister repo, and this
stream makes that orchestration visible in real time. This is particularly
useful because the monitor relies on debounced and coalesced work rather than a
single monolithic reconcile loop.

New task subscribers are also seeded with a small recent history, so `watch
tasks` is useful even if you attach after interesting work has already
happened. That retained history is backed by another sister repo, the
[`ring`](https://github.com/kahoon/ring) package, which keeps the replay path
simple and bounded.

The task stream includes events such as:

- `scheduled`
- `rescheduled`
- `executing`
- `executed`
- `cancelled`
- `failed`

along with task metadata when available:

- task id
- schedule delay
- execution duration
- error text

Example:

```text
[2026-04-15T17:20:19-04:00] scheduled   refresh:upstream delay=0s
[2026-04-15T17:20:19-04:00] executed    refresh:upstream duration=49.345483ms
[2026-04-15T17:20:57-04:00] scheduled   refresh:interface:event:eno1 delay=8s
[2026-04-15T17:20:57-04:00] rescheduled refresh:interface:event:eno1
[2026-04-15T17:21:05-04:00] executed    refresh:interface:event:eno1 duration=758.411µs
```

That output is not just “nice to have” logging. It makes several design choices
concrete and inspectable:

- link/address/route churn is debounced into one settled interface refresh
- periodic tasks and event-driven tasks use the same scheduler primitive
- runtime services like the stats reporter are treated as managed tasks
- failures inside scheduled work become visible without requiring ad hoc logging

In practice, `watch tasks` turns the daemon into something you can reason about
interactively. Instead of guessing why a refresh happened, whether a debounce
fired, or whether a task was replaced, you can watch the scheduler make those
decisions live, and you can still see the most recent task activity even if
you connect a few moments late.

### `watch checks`: recent and live check transitions

`netmonctl watch checks` sits between the high-level `watch` stream and the
lower-level task/trace surfaces.

It replays the most recent individual check transitions, then stays attached for
future ones. Each event shows one check moving from its previous severity to its
new severity, along with the current summary and detail when present.

This is useful when you want to answer:

- which specific check changed
- whether a condition degraded or recovered
- what the newest non-OK summary/detail is

Example:

```text
[2026-04-20T20:14:03-04:00] external-dns-v6     OK -> WARN  external DNS over IPv6 degraded
  root: ok; recursive: timeout
[2026-04-20T20:14:11-04:00] pihole-dns-v6       OK -> CRIT  Pi-hole DNS over IPv6 failing
  timeout
```

### Why the three streams are separate

The split between `watch status`, `watch checks`, and `watch tasks` is deliberate.

- `watch status` is for the appliance operator
- `watch checks` is for understanding health transitions at the check level
- `watch tasks` is for debugging, development, and understanding the scheduler

Keeping them separate avoids mixing user-facing health state with internal
activity. The first stream tells you what the appliance believes. The second
tells you how individual checks moved. The third tells you how the daemon got
there.

### Implementation notes

The streaming layer is intentionally narrow.

- The daemon uses server-streaming Connect RPCs and HTTP/2 over a Unix domain socket.
- `watch status` is backed by a status broadcaster that only emits on effective health
  changes.
- `watch tasks` is backed by the
  [`pending`](https://github.com/kahoon/pending) `TelemetryHandler`
  implementation used by the monitor.
- Recent task history is retained in a bounded
  [`ring`](https://github.com/kahoon/ring) buffer and replayed to new
  `watch tasks` subscribers before live task events continue.
- Both streams use buffered, non-blocking fanout so a slow client cannot stall
  the monitor.
- For status updates, the broadcaster uses a “latest value wins” policy rather
  than an unbounded event queue.

This keeps the streaming features useful in production, while also making the
control flow of the daemon visible enough to study and extend.

## systemd

Example unit:

```ini
[Unit]
Description=netmon network health monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
RuntimeDirectory=netmon
EnvironmentFile=/etc/default/netmon
ExecStart=/usr/sbin/netmond
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Example install:

```bash
sudo install -m 0755 ./netmond /usr/sbin/netmond
sudo install -m 0755 ./netmonctl /usr/sbin/netmonctl
sudo install -m 0644 ./contrib/netmon.env.example /etc/default/netmon
sudo install -m 0644 ./contrib/netmon.service /etc/systemd/system/netmon.service
sudo systemctl daemon-reload
sudo systemctl enable --now netmon
```

Edit `/etc/default/netmon` for your environment before starting the service.

## How It Works

1. Look up the monitored interface.
2. Subscribe to link, address, and route updates with netlink.
3. Debounce interface bursts for `8s`.
4. Refresh interface, listeners, upstream reachability, local Unbound validation, local Pi-hole state, and local Tailscale state on separate schedules.
5. Evaluate a fixed set of checks against the latest collected state.
6. Notify only if a check changed or the observed public IPv4 or IPv6 changed.

By default the schedulers run on these cadences:

- interface poll: `10m`
- listener poll: `10m`
- upstream poll: `5m`
- unbound poll: `5m`
- pihole poll: `5m`
- tailscale poll: `5m`
- runtime stats: `168h`

## Notes

- This is Linux-specific.
- Deployment helpers live under `contrib/`.
- Protobuf and Connect stubs are generated with Buf from `proto/netmon/v1/netmon.proto`.
- It currently posts to `https://ntfy.sh/<topic>`.
- It reads listener state from procfs rather than shelling out to `ss` or
  `netstat`.
- Upstream DNS health combines direct root `NS .` probes with recursive
  correctness checks against the same pinned root hostnames.
- Public IPv4 and public IPv6 observation both use DNS-based provider chains
  with deterministic fallback.
- DNSSEC validation is tested directly against local Unbound on `127.0.0.1:5335`
  using one positive and one negative validation query.
- Pi-hole service health is tested directly against the local client-facing DNS
  listeners on `127.0.0.1:53` and `::1:53`, while Pi-hole control-plane state
  is read from the v6 API using a short-lived session token.
- Pi-hole latency windows are retained in a bounded
  [`ring`](https://github.com/kahoon/ring) buffer so the trend logic stays
  fixed-size without steady-state slice churn.
- Tailscale reachability is intentionally narrow for alerting. The check answers
  whether the host remains connected to the tailnet, while peer counts,
  exit-node status, and advertised routes are exposed as state for future
  dashboard use.
- Notification delivery resolves the notification host through a dedicated
  fallback resolver instead of the local system resolver.
