package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kahoon/netmon/internal/model"
	"github.com/kahoon/ring"
)

// fakePiHoleClient implements PiHoleClient for testing.
type fakePiHoleClient struct {
	blocking    string
	blockingErr error

	core, web, ftl string
	versionsErr    error

	upstreams    []string
	upstreamsErr error

	summary    PiHoleSummary
	summaryErr error
}

func (f fakePiHoleClient) GetBlocking(_ context.Context) (string, error) {
	return f.blocking, f.blockingErr
}

func (f fakePiHoleClient) GetVersions(_ context.Context) (string, string, string, error) {
	return f.core, f.web, f.ftl, f.versionsErr
}

func (f fakePiHoleClient) GetUpstreams(_ context.Context) ([]string, error) {
	return f.upstreams, f.upstreamsErr
}

func (f fakePiHoleClient) GetSummary(_ context.Context) (PiHoleSummary, error) {
	return f.summary, f.summaryErr
}

func TestNormalizePiHoleUpstream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1#5335", "127.0.0.1#5335"},
		{"::1", "::1"},
		{"::1#5335", "::1#5335"},
		{"[::1]#5335", "::1#5335"},             // brackets stripped
		{"127.0.0.1# 5335 ", "127.0.0.1#5335"}, // whitespace around port trimmed
		{"127.0.0.1#", "127.0.0.1"},            // empty port treated as absent
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got := normalizePiHoleUpstream(tt.in)
			if got != tt.want {
				t.Fatalf("normalizePiHoleUpstream(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPiholeUpstreamsMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		actual   []string
		expected []string
		want     bool
	}{
		{
			name:     "exact match",
			actual:   []string{"127.0.0.1#5335", "::1#5335"},
			expected: []string{"127.0.0.1#5335", "::1#5335"},
			want:     true,
		},
		{
			name:     "order independent",
			actual:   []string{"::1#5335", "127.0.0.1#5335"},
			expected: []string{"127.0.0.1#5335", "::1#5335"},
			want:     true,
		},
		{
			name:     "bracket normalization",
			actual:   []string{"[::1]#5335", "127.0.0.1#5335"},
			expected: []string{"::1#5335", "127.0.0.1#5335"},
			want:     true,
		},
		{
			name:     "mismatch",
			actual:   []string{"8.8.8.8#53", "::1#5335"},
			expected: []string{"127.0.0.1#5335", "::1#5335"},
			want:     false,
		},
		{
			name:     "empty actual",
			actual:   []string{},
			expected: []string{"127.0.0.1#5335"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := piholeUpstreamsMatch(tt.actual, tt.expected)
			if got != tt.want {
				t.Fatalf("piholeUpstreamsMatch(%v, %v) = %v, want %v", tt.actual, tt.expected, got, tt.want)
			}
		})
	}
}

func TestClassifyPiHoleCollectionFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		kind    model.CollectionFailureKind
		summary string
	}{
		{
			name:    "authentication sentinel",
			err:     errPiHoleAuthentication,
			kind:    model.CollectionFailureAuthentication,
			summary: "Pi-hole API authentication failed",
		},
		{
			name:    "unauthorized response",
			err:     piHoleAPIError{Code: 401, Message: "unauthorized"},
			kind:    model.CollectionFailureAuthentication,
			summary: "Pi-hole API authentication failed",
		},
		{
			name:    "server response",
			err:     piHoleAPIError{Code: 500, Message: "internal server error"},
			kind:    model.CollectionFailureGeneric,
			summary: "Pi-hole API request failed",
		},
		{
			name:    "invalid response",
			err:     errPiHoleInvalidResponse,
			kind:    model.CollectionFailureInvalidResponse,
			summary: "Pi-hole API response invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classifyPiHoleCollectionFailure(tt.err)
			if got.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", got.Kind, tt.kind)
			}
			if got.Summary != tt.summary {
				t.Fatalf("Summary = %q, want %q", got.Summary, tt.summary)
			}
			if got.Detail == "" {
				t.Fatal("Detail is empty, want original error text")
			}
		})
	}
}

func TestPiHoleCollectorSetsCollectionFailure(t *testing.T) {
	t.Parallel()

	collector := &PiHoleCollector{
		Client:            fakePiHoleClient{blockingErr: errPiHoleAuthentication},
		ProbeTimeout:      time.Millisecond,
		GravityMaxAge:     defaultGravityMaxAge,
		ExpectedUpstreams: append([]string{}, defaultPiHoleExpectedUpstreams...),
		latencyV4:         ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize)),
		latencyV6:         ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	state, err := collector.Collect(ctx)
	if err == nil {
		t.Fatal("Collect() error = nil, want collection error")
	}
	if got, want := state.CollectionFailure.Kind, model.CollectionFailureAuthentication; got != want {
		t.Fatalf("CollectionFailure.Kind = %q, want %q", got, want)
	}
	if got, want := state.CollectionFailure.Summary, "Pi-hole API authentication failed"; got != want {
		t.Fatalf("CollectionFailure.Summary = %q, want %q", got, want)
	}
	if got, want := state.CollectionError, errPiHoleAuthentication.Error(); got != want {
		t.Fatalf("CollectionError = %q, want %q", got, want)
	}
}

// makeLatencyQueue pushes samples into a new ring queue in order.
func makeLatencyQueue(samples []time.Duration) *ring.Queue[time.Duration] {
	q := ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize))
	for _, s := range samples {
		q.Push(s)
	}
	return q
}

func TestClassifyLatencyTrend(t *testing.T) {
	t.Parallel()

	// With the current constants:
	//   trendMinSamples  = 8  (latencySampleSize/2)
	//   trendRecentCount = 4  (latencySampleSize/4)
	// An 8-sample queue splits into 4 prior + 4 recent.
	// threshold = max(trendDeltaAbs=5ms, prior*trendDeltaPct/100=prior*20%)

	tests := []struct {
		name    string
		samples []time.Duration // nil → pass a nil *ring.Queue
		want    model.LatencyTrend
	}{
		{
			name:    "nil queue",
			samples: nil,
			want:    model.LatencyTrendUnknown,
		},
		{
			name:    "too few samples",
			samples: repeat(10*time.Millisecond, trendMinSamples-1),
			want:    model.LatencyTrendUnknown,
		},
		{
			name:    "all equal",
			samples: repeat(10*time.Millisecond, trendMinSamples),
			want:    model.LatencyTrendStable,
		},
		{
			// prior=10ms, threshold=max(5ms,2ms)=5ms
			// recent=14ms, delta=4ms < 5ms → Stable
			name:    "small absolute change stays stable",
			samples: concat(repeat(10*time.Millisecond, 4), repeat(14*time.Millisecond, 4)),
			want:    model.LatencyTrendStable,
		},
		{
			// prior=10ms, threshold=5ms
			// recent=20ms >= 10+5=15ms → Rising
			name:    "rising",
			samples: concat(repeat(10*time.Millisecond, 4), repeat(20*time.Millisecond, 4)),
			want:    model.LatencyTrendRising,
		},
		{
			// prior=10ms, threshold=5ms
			// recent=4ms <= 10-5=5ms → Falling
			name:    "falling",
			samples: concat(repeat(10*time.Millisecond, 4), repeat(4*time.Millisecond, 4)),
			want:    model.LatencyTrendFalling,
		},
		{
			// prior=100ms, threshold=max(5ms,20ms)=20ms
			// recent=125ms >= 100+20=120ms → Rising
			name:    "rising large prior",
			samples: concat(repeat(100*time.Millisecond, 4), repeat(125*time.Millisecond, 4)),
			want:    model.LatencyTrendRising,
		},
		{
			// prior=100ms, threshold=20ms
			// recent=115ms, 115 < 120 → Stable (real change but below 20% threshold)
			name:    "medium change stays stable",
			samples: concat(repeat(100*time.Millisecond, 4), repeat(115*time.Millisecond, 4)),
			want:    model.LatencyTrendStable,
		},
		{
			// prior=100ms, threshold=20ms
			// recent=79ms <= 100-20=80ms → Falling
			name:    "falling large prior",
			samples: concat(repeat(100*time.Millisecond, 4), repeat(79*time.Millisecond, 4)),
			want:    model.LatencyTrendFalling,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var q *ring.Queue[time.Duration]
			if tt.samples != nil {
				q = makeLatencyQueue(tt.samples)
			}
			got := classifyLatencyTrend(q)
			if got != tt.want {
				t.Fatalf("classifyLatencyTrend() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildLatencyWindow(t *testing.T) {
	t.Parallel()

	t.Run("empty queue", func(t *testing.T) {
		t.Parallel()
		q := ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize))
		w := buildLatencyWindow(q)
		if w.Trend != model.LatencyTrendUnknown {
			t.Fatalf("Trend = %q, want Unknown", w.Trend)
		}
		if w.Samples != 0 {
			t.Fatalf("Samples = %d, want 0", w.Samples)
		}
	})

	t.Run("single sample", func(t *testing.T) {
		t.Parallel()
		q := makeLatencyQueue([]time.Duration{42 * time.Millisecond})
		w := buildLatencyWindow(q)
		if w.Last != 42*time.Millisecond {
			t.Fatalf("Last = %v, want 42ms", w.Last)
		}
		if w.Average != 42*time.Millisecond {
			t.Fatalf("Average = %v, want 42ms", w.Average)
		}
		if w.Max != 42*time.Millisecond {
			t.Fatalf("Max = %v, want 42ms", w.Max)
		}
		if w.Samples != 1 {
			t.Fatalf("Samples = %d, want 1", w.Samples)
		}
		if w.Trend != model.LatencyTrendUnknown {
			t.Fatalf("Trend = %q, want Unknown (too few samples for trend)", w.Trend)
		}
	})

	t.Run("multiple samples", func(t *testing.T) {
		t.Parallel()
		ms := []time.Duration{5, 10, 20, 30, 15, 25, 8, 12}
		for i, v := range ms {
			ms[i] = v * time.Millisecond
		}
		q := makeLatencyQueue(ms)
		w := buildLatencyWindow(q)

		if w.Last != 12*time.Millisecond {
			t.Fatalf("Last = %v, want 12ms", w.Last)
		}
		if w.Max != 30*time.Millisecond {
			t.Fatalf("Max = %v, want 30ms", w.Max)
		}
		if w.Samples != 8 {
			t.Fatalf("Samples = %d, want 8", w.Samples)
		}

		wantAvg := (5 + 10 + 20 + 30 + 15 + 25 + 8 + 12) * time.Millisecond / 8
		if w.Average != wantAvg {
			t.Fatalf("Average = %v, want %v", w.Average, wantAvg)
		}
	})
}

func newTestCollector(client PiHoleClient) *PiHoleCollector {
	return &PiHoleCollector{
		Client:            client,
		ProbeTimeout:      time.Millisecond, // fail fast — no Pi-hole in test env
		GravityMaxAge:     defaultGravityMaxAge,
		ExpectedUpstreams: append([]string{}, defaultPiHoleExpectedUpstreams...),
		latencyV4:         ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize)),
		latencyV6:         ring.New[time.Duration](ring.WithMinCapacity[time.Duration](latencySampleSize)),
	}
}

func TestPiHoleCollectorCollect(t *testing.T) {
	t.Parallel()

	gravityUpdated := time.Now().Add(-24 * time.Hour) // fresh enough

	c := newTestCollector(fakePiHoleClient{
		blocking:  "enabled",
		core:      "v6.0.0",
		web:       "v6.0.0",
		ftl:       "v6.0.0",
		upstreams: []string{"127.0.0.1#5335", "::1#5335"},
		summary: PiHoleSummary{
			QueriesTotal:   1000,
			QueriesBlocked: 300,
			CacheHits:      200,
			Forwarded:      500,
			ClientsActive:  5,
			DomainsBlocked: 150000,
			GravityUpdated: gravityUpdated,
		},
	})

	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if got, want := state.Status.Blocking, "enabled"; got != want {
		t.Errorf("Status.Blocking = %q, want %q", got, want)
	}
	if got, want := state.Status.CoreVersion, "v6.0.0"; got != want {
		t.Errorf("Status.CoreVersion = %q, want %q", got, want)
	}
	if got, want := state.Status.FTLVersion, "v6.0.0"; got != want {
		t.Errorf("Status.FTLVersion = %q, want %q", got, want)
	}
	if !state.Upstreams.MatchesExpected {
		t.Error("Upstreams.MatchesExpected = false, want true")
	}
	if got, want := state.Counters.QueriesTotal, uint64(1000); got != want {
		t.Errorf("Counters.QueriesTotal = %d, want %d", got, want)
	}
	if got, want := state.Counters.QueriesBlocked, uint64(300); got != want {
		t.Errorf("Counters.QueriesBlocked = %d, want %d", got, want)
	}
	if got, want := state.Counters.CacheHits, uint64(200); got != want {
		t.Errorf("Counters.CacheHits = %d, want %d", got, want)
	}
	if got, want := state.Counters.ClientsActive, uint64(5); got != want {
		t.Errorf("Counters.ClientsActive = %d, want %d", got, want)
	}
	if got, want := state.Gravity.DomainsBlocked, uint64(150000); got != want {
		t.Errorf("Gravity.DomainsBlocked = %d, want %d", got, want)
	}
	if state.Gravity.Stale {
		t.Error("Gravity.Stale = true, want false (gravity updated 24h ago)")
	}
}

func TestPiHoleCollectorCollect_upstreamMismatch(t *testing.T) {
	t.Parallel()

	c := newTestCollector(fakePiHoleClient{
		blocking:  "enabled",
		upstreams: []string{"8.8.8.8#53"},
		summary:   PiHoleSummary{GravityUpdated: time.Now()},
	})

	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if state.Upstreams.MatchesExpected {
		t.Error("Upstreams.MatchesExpected = true, want false")
	}
}

func TestPiHoleCollectorCollect_staleGravity(t *testing.T) {
	t.Parallel()

	c := newTestCollector(fakePiHoleClient{
		blocking:  "enabled",
		upstreams: []string{"127.0.0.1#5335", "::1#5335"},
		summary: PiHoleSummary{
			GravityUpdated: time.Now().Add(-8 * 24 * time.Hour), // older than 7-day max
		},
	})

	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if !state.Gravity.Stale {
		t.Error("Gravity.Stale = false, want true (gravity is > 7 days old)")
	}
}

func TestPiHoleCollectorCollect_apiErrors(t *testing.T) {
	t.Parallel()

	apiErr := errors.New("connection refused")

	c := newTestCollector(fakePiHoleClient{
		blockingErr:  apiErr,
		upstreamsErr: apiErr,
		summaryErr:   apiErr,
	})

	state, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("Collect() error = nil, want error from blocking failure")
	}
	if state.Status.Detail == "" {
		t.Error("Status.Detail is empty, want error detail")
	}
	if state.Upstreams.Detail == "" {
		t.Error("Upstreams.Detail is empty, want error detail")
	}
	if state.Gravity.Detail == "" {
		t.Error("Gravity.Detail is empty, want error detail")
	}
	if state.Counters.Detail == "" {
		t.Error("Counters.Detail is empty, want error detail")
	}
}

func repeat(d time.Duration, n int) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func concat(slices ...[]time.Duration) []time.Duration {
	var out []time.Duration
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
