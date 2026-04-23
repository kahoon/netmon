package main

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestRPCDiagnostic(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantSummary  string
		wantCause    string
		wantDetected bool
	}{
		{
			name:         "socket missing",
			err:          &net.OpError{Err: &os.SyscallError{Err: syscall.ENOENT}},
			wantSummary:  "cannot reach netmond",
			wantCause:    "socket not found",
			wantDetected: true,
		},
		{
			name:         "connection refused",
			err:          &net.OpError{Err: &os.SyscallError{Err: syscall.ECONNREFUSED}},
			wantSummary:  "cannot reach netmond",
			wantCause:    "connection refused",
			wantDetected: true,
		},
		{
			name:         "deadline exceeded",
			err:          context.DeadlineExceeded,
			wantSummary:  "netmond did not respond in time",
			wantCause:    "request timed out",
			wantDetected: true,
		},
		{
			name:         "other error",
			err:          errors.New("boom"),
			wantDetected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := rpcDiagnostic(tc.err)
			if ok != tc.wantDetected {
				t.Fatalf("rpcDiagnostic() detected = %t, want %t", ok, tc.wantDetected)
			}
			if !tc.wantDetected {
				return
			}
			if got.summary != tc.wantSummary {
				t.Fatalf("rpcDiagnostic().summary = %q, want %q", got.summary, tc.wantSummary)
			}
			if got.cause != tc.wantCause {
				t.Fatalf("rpcDiagnostic().cause = %q, want %q", got.cause, tc.wantCause)
			}
		})
	}
}
