package stats

import (
	"testing"
	"time"

	"github.com/kahoon/netmon/internal/events"
)

func TestRecorderAggregatesEvents(t *testing.T) {
	recorder := NewRecorder()
	now := time.Now()

	recorder.Handle(events.LinkEvent{At: now})
	recorder.Handle(events.CollectorStarted{At: now, Collector: "upstream", Reason: "trace refresh"})
	recorder.Handle(events.CollectorFinished{At: now, Collector: "upstream", Reason: "trace refresh", Duration: 10 * time.Millisecond})
	recorder.Handle(events.TaskScheduled{At: now, ID: "refresh:upstream", Delay: time.Second})
	recorder.Handle(events.TaskExecuting{At: now, ID: "refresh:upstream"})
	recorder.Handle(events.TaskExecuted{At: now, ID: "refresh:upstream", Duration: 20 * time.Millisecond})
	recorder.Handle(events.ProbeResult{At: now, Kind: "root", Family: "ipv4", Status: "ok"})
	recorder.Handle(events.ChecksEvaluated{At: now, Reason: "trace refresh", Changed: 2, Passed: 5, Failed: 1})
	recorder.Handle(events.NotificationSent{At: now, Title: "updated", Severity: "WARN"})
	recorder.Handle(events.TraceStarted{At: now, TraceID: "abc", Scope: "upstream"})
	recorder.Handle(events.TraceCompleted{At: now, TraceID: "abc", Scope: "upstream", Duration: 20 * time.Millisecond})

	snapshot := recorder.Snapshot()

	if got, want := snapshot.Events.Link, uint64(1); got != want {
		t.Fatalf("Events.Link = %d, want %d", got, want)
	}
	if got, want := snapshot.Collectors["upstream"].Started, uint64(1); got != want {
		t.Fatalf("Collectors[upstream].Started = %d, want %d", got, want)
	}
	if got, want := snapshot.Collectors["upstream"].Finished, uint64(1); got != want {
		t.Fatalf("Collectors[upstream].Finished = %d, want %d", got, want)
	}
	if got, want := snapshot.CollectorRuns["trace refresh"], uint64(1); got != want {
		t.Fatalf("CollectorRuns[trace refresh] = %d, want %d", got, want)
	}
	if got, want := snapshot.TasksByID["refresh:upstream"].Scheduled, uint64(1); got != want {
		t.Fatalf("TasksByID[refresh:upstream].Scheduled = %d, want %d", got, want)
	}
	if got, want := snapshot.TasksByID["refresh:upstream"].Executing, uint64(1); got != want {
		t.Fatalf("TasksByID[refresh:upstream].Executing = %d, want %d", got, want)
	}
	if got, want := snapshot.Probes["root/ipv4"].Success, uint64(1); got != want {
		t.Fatalf("Probes[root/ipv4].Success = %d, want %d", got, want)
	}
	if got, want := snapshot.Checks.Passed, uint64(5); got != want {
		t.Fatalf("Checks.Passed = %d, want %d", got, want)
	}
	if got, want := snapshot.Notifications.Sent, uint64(1); got != want {
		t.Fatalf("Notifications.Sent = %d, want %d", got, want)
	}
	if got, want := snapshot.Traces.Completed, uint64(1); got != want {
		t.Fatalf("Traces.Completed = %d, want %d", got, want)
	}
}
