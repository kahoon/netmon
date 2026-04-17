GOCACHE ?= /tmp/netmon-gocache
GOOS ?= linux
GOARCH ?= amd64
BUF ?= $(shell go env GOPATH)/bin/buf
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date +%Y-%m-%dT%H:%M:%S%z)

LDFLAGS := -X github.com/kahoon/netmon/internal/version.Version=$(VERSION) \
	-X github.com/kahoon/netmon/internal/version.Commit=$(COMMIT) \
	-X github.com/kahoon/netmon/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: build build-linux test fmt generate clean

build-linux:
	@GOCACHE="$(GOCACHE)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" go build -ldflags '$(LDFLAGS)' ./cmd/netmond
	@GOCACHE="$(GOCACHE)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" go build -ldflags '$(LDFLAGS)' ./cmd/netmonctl

build:
	@go build -ldflags '$(LDFLAGS)' ./cmd/netmond
	@go build -ldflags '$(LDFLAGS)' ./cmd/netmonctl

generate:
	@"$(BUF)" generate

test:
	@GOCACHE="$(GOCACHE)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" go test -c -o /tmp/netmon-model.test ./internal/model
	@GOCACHE="$(GOCACHE)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" go test -c -o /tmp/netmon-collector.test ./internal/collector
	@GOCACHE="$(GOCACHE)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" go test -c -o /tmp/netmon-monitor.test ./internal/monitor
	@GOCACHE="$(GOCACHE)" GOOS="$(GOOS)" GOARCH="$(GOARCH)" go test -c -o /tmp/netmon-rpc.test ./internal/rpc

fmt:
	@gofmt -w cmd/netmond/main.go cmd/netmonctl/main.go internal/config/*.go internal/model/*.go internal/collector/*.go internal/monitor/*.go internal/rpc/*.go internal/version/*.go

clean:
	@rm -rf netmond netmonctl /tmp/netmon*.test proto/netmon/v1/*.go proto/netmon/v1/netmonv1connect/*.go $(GOCACHE)
	@make generate
