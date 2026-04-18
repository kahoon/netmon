package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/monitor"
	"github.com/kahoon/netmon/internal/rpc"
	"github.com/kahoon/netmon/internal/version"
	"golang.org/x/sync/errgroup"
)

func main() {
	// Load env configuration
	cfg := config.LoadConfig()
	log.Printf(
		"starting netmond version=%s commit=%s build_time=%s",
		version.Version,
		version.Commit,
		version.BuildTime,
	)
	// Create a context that is canceled on SIGINT or SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Initialize the monitor which will monitor the different subsystems we're interested in.
	daemon := monitor.NewMonitor(cfg)
	if err := daemon.Initialize(ctx); err != nil {
		log.Fatalf("initialization failed: %v", err)
	}
	// Run the monitor and RPC server concurrently, and wait for them to exit.
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return daemon.Run(groupCtx)
	})
	group.Go(func() error {
		return rpc.ServeUnix(groupCtx, cfg.RPCSocketPath, daemon)
	})

	if err := group.Wait(); err != nil && err != context.Canceled {
		log.Fatalf("daemon failed: %v", err)
	}
}
