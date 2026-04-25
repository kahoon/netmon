package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/ring"
	"github.com/miekg/dns"
)

const (
	piHoleDNSPort        = "53"
	defaultPiHoleAPIURL  = "http://127.0.0.1/api"
	defaultGravityMaxAge = 7 * 24 * time.Hour

	// Latency trend analysis parameters
	latencySampleSize = 16
	trendRecentCount  = latencySampleSize / 4 // recent window: last 25% of samples
	trendMinSamples   = latencySampleSize / 2 // require at least half the ring filled
	trendDeltaAbs     = 5 * time.Millisecond
	trendDeltaPct     = 20
)

var defaultPiHoleExpectedUpstreams = []string{
	"127.0.0.1#5335",
	"::1#5335",
}

type PiHoleCollector struct {
	Client            PiHoleClient
	ProbeTimeout      time.Duration
	GravityMaxAge     time.Duration
	ExpectedUpstreams []string

	mu        sync.Mutex
	latencyV4 *ring.Queue[time.Duration]
	latencyV6 *ring.Queue[time.Duration]
}

func NewPiHoleCollector(cfg config.Config) *PiHoleCollector {
	return &PiHoleCollector{
		Client: NewPiHoleClient(defaultPiHoleAPIURL, cfg.PiHolePassword, &http.Client{
			Timeout: cfg.HTTPTimeout,
		}),
		ProbeTimeout:      cfg.DNSProbeTimeout,
		GravityMaxAge:     defaultGravityMaxAge,
		ExpectedUpstreams: append([]string{}, defaultPiHoleExpectedUpstreams...),
		latencyV4:         ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize)),
		latencyV6:         ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize)),
	}
}

func (c *PiHoleCollector) Collect(ctx context.Context) (model.PiHoleState, error) {
	state := model.PiHoleState{
		DNSV4: c.probeDNS(ctx, "udp4", "127.0.0.1", dns.TypeA),
		DNSV6: c.probeDNS(ctx, "udp6", "::1", dns.TypeAAAA),
	}
	c.recordSample("ipv4", state.DNSV4)
	c.recordSample("ipv6", state.DNSV6)
	state.LatencyIPv4 = c.snapshotLatency("ipv4")
	state.LatencyIPv6 = c.snapshotLatency("ipv6")

	// GetBlocking is the primary API health check. A failure here means the
	// Pi-hole API is unreachable, so we surface it as a collection error and
	// skip the remaining API calls (they would fail too).
	blocking, err := c.Client.GetBlocking(ctx)
	if err != nil {
		state.Status.Detail = err.Error()
		state.Upstreams.Detail = err.Error()
		state.Gravity.Detail = err.Error()
		state.Counters.Detail = err.Error()
		state.CollectionFailure = classifyPiHoleCollectionFailure(err)
		state.CollectionError = state.CollectionFailure.Detail
		return state, err
	}
	state.Status.Blocking = blocking

	if core, web, ftl, err := c.Client.GetVersions(ctx); err == nil {
		state.Status.CoreVersion = core
		state.Status.WebVersion = web
		state.Status.FTLVersion = ftl
	}

	if upstreams, err := c.Client.GetUpstreams(ctx); err != nil {
		state.Upstreams.Detail = err.Error()
	} else {
		state.Upstreams.Servers = model.SortedUnique(normalizePiHoleUpstreams(upstreams))
		state.Upstreams.MatchesExpected = piholeUpstreamsMatch(state.Upstreams.Servers, c.ExpectedUpstreams)
	}

	if summary, err := c.Client.GetSummary(ctx); err != nil {
		state.Gravity.Detail = err.Error()
		state.Counters.Detail = err.Error()
	} else {
		state.Gravity.LastUpdated = summary.GravityUpdated
		state.Gravity.DomainsBlocked = summary.DomainsBlocked
		state.Gravity.Stale = summary.GravityUpdated.IsZero() || time.Since(summary.GravityUpdated) > c.GravityMaxAge
		state.Counters = model.PiHoleCounters{
			QueriesTotal:   summary.QueriesTotal,
			QueriesBlocked: summary.QueriesBlocked,
			CacheHits:      summary.CacheHits,
			Forwarded:      summary.Forwarded,
			ClientsActive:  summary.ClientsActive,
		}
	}

	return state, nil
}

func classifyPiHoleCollectionFailure(err error) model.CollectionFailure {
	switch {
	case isPiHoleAuthenticationError(err):
		return model.NewCollectionFailure(
			model.CollectionFailureAuthentication,
			"Pi-hole API authentication failed",
			err,
		)
	case isPiHoleUnavailableError(err):
		return model.NewCollectionFailure(
			model.CollectionFailureUnavailable,
			"Pi-hole API unreachable",
			err,
		)
	case isPiHoleInvalidResponseError(err):
		return model.NewCollectionFailure(
			model.CollectionFailureInvalidResponse,
			"Pi-hole API response invalid",
			err,
		)
	case isPiHoleAPIError(err):
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"Pi-hole API request failed",
			err,
		)
	default:
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"Pi-hole collection failed",
			err,
		)
	}
}

func isPiHoleAuthenticationError(err error) bool {
	if errors.Is(err, errPiHoleAuthentication) {
		return true
	}
	apiErr, ok := errors.AsType[piHoleAPIError](err)
	return ok && (apiErr.Code == http.StatusUnauthorized || apiErr.Code == http.StatusForbidden)
}

func isPiHoleUnavailableError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if _, ok := errors.AsType[net.Error](err); ok {
		return true
	}
	if _, ok := errors.AsType[*net.OpError](err); ok {
		return true
	}
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		switch errno {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ETIMEDOUT:
			return true
		}
	}
	return false
}

func isPiHoleInvalidResponseError(err error) bool {
	if errors.Is(err, errPiHoleInvalidResponse) {
		return true
	}
	if _, ok := errors.AsType[*json.SyntaxError](err); ok {
		return true
	}
	_, ok := errors.AsType[*json.UnmarshalTypeError](err)
	return ok
}

func isPiHoleAPIError(err error) bool {
	_, ok := errors.AsType[piHoleAPIError](err)
	return ok
}

func (c *PiHoleCollector) probeDNS(ctx context.Context, network, host string, qtype uint16) model.DNSProbeResult {
	var failures []string

	for _, target := range rootTargets {
		probe := c.queryExpectedAddress(ctx, network, host, qtype, target)
		emitProbeTrace(ctx, "pihole_dns", network, target.Name, "Pi-hole", probe)
		if probe.OK() {
			return probe
		}
		failures = append(failures, formatProbeFailure(probe))
	}

	return model.DNSProbeResult{
		Status: model.DNSProbeStatusNetworkError,
		Detail: strings.Join(failures, "; "),
	}
}

func (c *PiHoleCollector) queryExpectedAddress(ctx context.Context, network, host string, qtype uint16, target rootTarget) model.DNSProbeResult {
	msg := new(dns.Msg)
	msg.SetQuestion(target.Name, qtype)
	msg.RecursionDesired = true

	expected := target.IPv4
	if qtype == dns.TypeAAAA {
		expected = target.IPv6
	}

	answer, latency, err := exchange(ctx, c.ProbeTimeout, network, host, piHoleDNSPort, msg)
	if err != nil {
		return model.DNSProbeResult{
			Name:    fmt.Sprintf("%s via Pi-hole", target.Name),
			Target:  net.JoinHostPort(host, piHoleDNSPort),
			Status:  classifyExchangeError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	status, detail := validateExpectedAddressAnswer(answer, qtype, expected)
	return model.DNSProbeResult{
		Name:    fmt.Sprintf("%s via Pi-hole", target.Name),
		Target:  net.JoinHostPort(host, piHoleDNSPort),
		Status:  status,
		Latency: latency,
		Detail:  detail,
	}
}

func (c *PiHoleCollector) recordSample(family string, probe model.DNSProbeResult) {
	if !probe.OK() || probe.Latency <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch family {
	case "ipv4":
		c.latencyV4.Push(probe.Latency)
	case "ipv6":
		c.latencyV6.Push(probe.Latency)
	}
}

func (c *PiHoleCollector) snapshotLatency(family string) model.DNSLatencyWindow {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch family {
	case "ipv4":
		return buildLatencyWindow(c.latencyV4)
	case "ipv6":
		return buildLatencyWindow(c.latencyV6)
	default:
		return model.DNSLatencyWindow{Trend: model.LatencyTrendUnknown}
	}
}

func buildLatencyWindow(samples *ring.Queue[time.Duration]) model.DNSLatencyWindow {
	if samples == nil || samples.Len() == 0 {
		return model.DNSLatencyWindow{Trend: model.LatencyTrendUnknown}
	}

	var sum time.Duration
	var max time.Duration
	var last time.Duration
	count := samples.Len()
	for sample := range samples.All() {
		value := *sample
		sum += value
		last = value
		if value > max {
			max = value
		}
	}

	window := model.DNSLatencyWindow{
		Last:    last,
		Average: sum / time.Duration(count),
		Max:     max,
		Samples: uint64(count),
		Trend:   model.LatencyTrendStable,
	}
	window.Trend = classifyLatencyTrend(samples)
	return window
}

func classifyLatencyTrend(samples *ring.Queue[time.Duration]) model.LatencyTrend {
	if samples == nil || samples.Len() < trendMinSamples {
		return model.LatencyTrendUnknown
	}

	count := samples.Len()
	split := count - trendRecentCount

	var priorSum, recentSum time.Duration
	var idx int
	for sample := range samples.All() {
		if idx < split {
			priorSum += *sample
		} else {
			recentSum += *sample
		}
		idx++
	}

	prior := priorSum / time.Duration(split)
	recent := recentSum / time.Duration(trendRecentCount)
	if prior <= 0 || recent <= 0 {
		return model.LatencyTrendUnknown
	}

	threshold := max(trendDeltaAbs, prior*trendDeltaPct/100)
	switch {
	case recent >= prior+threshold:
		return model.LatencyTrendRising
	case recent <= prior-threshold:
		return model.LatencyTrendFalling
	default:
		return model.LatencyTrendStable
	}
}

func normalizePiHoleUpstreams(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizePiHoleUpstream(value)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func normalizePiHoleUpstream(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	parts := strings.SplitN(value, "#", 2)
	host := strings.Trim(parts[0], "[]")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if len(parts) == 1 || strings.TrimSpace(parts[1]) == "" {
		return host
	}
	return host + "#" + strings.TrimSpace(parts[1])
}

func piholeUpstreamsMatch(actual, expected []string) bool {
	normalizedActual := model.SortedUnique(normalizePiHoleUpstreams(actual))
	normalizedExpected := model.SortedUnique(normalizePiHoleUpstreams(expected))
	return slices.Equal(normalizedActual, normalizedExpected)
}
