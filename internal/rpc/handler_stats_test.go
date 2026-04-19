package rpc

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"
	"github.com/kahoon/netmon/internal/stats"
	netmonv1 "github.com/kahoon/netmon/proto/netmon/v1"
)

func TestGetStatsMapsSnapshot(t *testing.T) {
	handler := &Handler{
		svc: &fakeService{
			snapshot: stats.Snapshot{
				Events: stats.EventCounters{Link: 1, Addr: 2, Route: 3},
				Collectors: map[string]stats.CollectorCounters{
					"upstream": {Started: 4, Finished: 3, Failed: 1},
				},
				CollectorRuns: map[string]uint64{"trace refresh": 2},
				Tasks:         stats.TaskCounters{Scheduled: 5, Executing: 4, Executed: 4},
				TasksByID: map[string]stats.TaskCounters{
					"refresh:upstream": {Scheduled: 2, Executing: 2, Executed: 2},
				},
				Probes: map[string]stats.OutcomeCounters{
					"root/ipv4": {Total: 6, Success: 5, Failure: 1},
				},
				Checks:        stats.CheckCounters{Evaluations: 7, Changed: 3, Passed: 20, Failed: 4},
				Notifications: stats.NotificationCounters{Sent: 1, Skipped: 2, Failed: 3},
				Traces:        stats.TraceCounters{Started: 2, Completed: 1, Failed: 1},
			},
		},
	}

	resp, err := handler.GetStats(context.Background(), connect.NewRequest(&netmonv1.GetStatsRequest{}))
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}

	if got, want := resp.Msg.GetEvents().GetAddr(), uint64(2); got != want {
		t.Fatalf("Events.Addr = %d, want %d", got, want)
	}
	if got, want := resp.Msg.GetCollectors()["upstream"].GetFailed(), uint64(1); got != want {
		t.Fatalf("Collectors[upstream].Failed = %d, want %d", got, want)
	}
	if got, want := resp.Msg.GetProbes()["root/ipv4"].GetSuccess(), uint64(5); got != want {
		t.Fatalf("Probes[root/ipv4].Success = %d, want %d", got, want)
	}
	if got, want := resp.Msg.GetTasks().GetExecuting(), uint64(4); got != want {
		t.Fatalf("Tasks.Executing = %d, want %d", got, want)
	}
	if got, want := resp.Msg.GetTraces().GetStarted(), uint64(2); got != want {
		t.Fatalf("Traces.Started = %d, want %d", got, want)
	}
}
