package rpc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kahoon/netmon/internal/monitor"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const shutdownTimeout = 5 * time.Second

func ServeUnix(ctx context.Context, socketPath string, svc monitor.Service) error {
	if socketPath == "" {
		return fmt.Errorf("rpc socket path not configured")
	}

	listener, err := listenUnix(socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()

	mux := http.NewServeMux()
	path, handler := NewHandler(svc)
	mux.Handle(path, handler)

	server := &http.Server{
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		errCh <- server.Shutdown(shutdownCtx)
	}()

	log.Printf("rpc server listening on unix://%s", socketPath)
	err = server.Serve(listener)
	var shutdownErr error
	if ctx.Err() != nil {
		shutdownErr = <-errCh
	}

	switch {
	case err == nil || errors.Is(err, http.ErrServerClosed):
		return shutdownErr
	case shutdownErr != nil && !errors.Is(shutdownErr, context.Canceled):
		return errors.Join(err, shutdownErr)
	default:
		return err
	}
}

func listenUnix(socketPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}

	info, err := os.Stat(socketPath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("rpc socket path exists and is not a socket: %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, err
	}
	return listener, nil
}
