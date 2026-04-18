package monitor

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strings"
	"time"
)

func runtimeStatsReporter(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			printRuntimeStats()
		}
	}
}

func printRuntimeStats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var report strings.Builder
	fmt.Fprintf(&report, "runtime stats\n")
	fmt.Fprintf(&report, "  go_version:      %s\n", runtime.Version())
	fmt.Fprintf(&report, "  os_arch:         %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&report, "  cpus:            %d\n", runtime.NumCPU())
	fmt.Fprintf(&report, "  goroutines:      %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&report, "  cgo_calls:       %d\n", runtime.NumCgoCall())
	fmt.Fprintf(&report, "  heap_alloc:      %s\n", formatBytes(mem.HeapAlloc))
	fmt.Fprintf(&report, "  heap_in_use:     %s\n", formatBytes(mem.HeapInuse))
	fmt.Fprintf(&report, "  heap_idle:       %s\n", formatBytes(mem.HeapIdle))
	fmt.Fprintf(&report, "  heap_sys:        %s\n", formatBytes(mem.HeapSys))
	fmt.Fprintf(&report, "  stack_in_use:    %s\n", formatBytes(mem.StackInuse))
	fmt.Fprintf(&report, "  total_alloc:     %s\n", formatBytes(mem.TotalAlloc))
	fmt.Fprintf(&report, "  sys:             %s\n", formatBytes(mem.Sys))
	fmt.Fprintf(&report, "  gc_cycles:       %d\n", mem.NumGC)
	fmt.Fprintf(&report, "  next_gc:         %s", formatBytes(mem.NextGC))
	if mem.NumGC > 0 {
		lastGC := time.Unix(0, int64(mem.LastGC))
		fmt.Fprintf(&report, "\n  last_gc:         %s", lastGC.Format(time.RFC3339))
		fmt.Fprintf(&report, "\n  last_gc_pause:   %s", time.Duration(mem.PauseNs[(mem.NumGC+255)%256]))
	}
	log.Print(report.String())
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
