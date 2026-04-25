package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/kahoon/netmon/internal/model"
)

const (
	tcpListenState = "0A"
	udpListenState = "07"
)

type ListenerCollector struct{}

func (c ListenerCollector) Collect(_ context.Context) (model.ListenerState, error) {
	var state model.ListenerState
	var err error

	state.DNS53TCP, err = probeListeningSockets(53, "tcp")
	if err != nil {
		return stateWithListenerFailure(state, fmt.Errorf("probe tcp/53: %w", err))
	}
	state.DNS53UDP, err = probeListeningSockets(53, "udp")
	if err != nil {
		return stateWithListenerFailure(state, fmt.Errorf("probe udp/53: %w", err))
	}
	state.Resolver5335TCP, err = probeListeningSockets(5335, "tcp")
	if err != nil {
		return stateWithListenerFailure(state, fmt.Errorf("probe tcp/5335: %w", err))
	}
	state.Resolver5335UDP, err = probeListeningSockets(5335, "udp")
	if err != nil {
		return stateWithListenerFailure(state, fmt.Errorf("probe udp/5335: %w", err))
	}

	return state, nil
}

func stateWithListenerFailure(state model.ListenerState, err error) (model.ListenerState, error) {
	state.CollectionFailure = classifyListenerCollectionFailure(err)
	state.CollectionError = state.CollectionFailure.Detail
	return state, err
}

func classifyListenerCollectionFailure(err error) model.CollectionFailure {
	switch {
	case errors.Is(err, os.ErrPermission):
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"listener collection permission denied",
			err,
		)
	case errors.Is(err, os.ErrNotExist):
		return model.NewCollectionFailure(
			model.CollectionFailureUnavailable,
			"listener socket table unavailable",
			err,
		)
	default:
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"listener collection failed",
			err,
		)
	}
}

func probeListeningSockets(port int, protocol string) (model.SocketProbe, error) {
	var files []struct {
		path   string
		family int
		state  string
	}

	switch protocol {
	case "tcp":
		files = []struct {
			path   string
			family int
			state  string
		}{
			{path: "/proc/net/tcp", family: 4, state: tcpListenState},
			{path: "/proc/net/tcp6", family: 6, state: tcpListenState},
		}
	case "udp":
		files = []struct {
			path   string
			family int
			state  string
		}{
			{path: "/proc/net/udp", family: 4, state: udpListenState},
			{path: "/proc/net/udp6", family: 6, state: udpListenState},
		}
	default:
		return model.SocketProbe{}, fmt.Errorf("unsupported protocol %q", protocol)
	}

	var combined model.SocketProbe
	for _, file := range files {
		probe, err := readProcSocketFile(file.path, port, file.family, file.state)
		if err != nil {
			return model.SocketProbe{}, err
		}
		combined = mergeSocketProbes(combined, probe)
	}

	return combined, nil
}

func readProcSocketFile(path string, port int, family int, listenState string) (model.SocketProbe, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.SocketProbe{}, err
	}
	defer file.Close()

	loopback := make(map[string]struct{})
	nonLoopback := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != listenState {
			continue
		}

		hostHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}

		parsedPort, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || int(parsedPort) != port {
			continue
		}

		ip, err := parseProcIP(hostHex, family)
		if err != nil {
			return model.SocketProbe{}, fmt.Errorf("%s line %d: %w", path, lineNum, err)
		}

		binding := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		if ip.IsLoopback() {
			loopback[binding] = struct{}{}
			continue
		}
		nonLoopback[binding] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return model.SocketProbe{}, err
	}

	return model.SocketProbe{
		Loopback:    sortedKeys(loopback),
		NonLoopback: sortedKeys(nonLoopback),
	}, nil
}

func parseProcIP(hexAddr string, family int) (net.IP, error) {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return nil, fmt.Errorf("decode address %q: %w", hexAddr, err)
	}

	switch family {
	case 4:
		if len(raw) != net.IPv4len {
			return nil, fmt.Errorf("unexpected ipv4 length %d", len(raw))
		}
		reverseBytes(raw)
		return net.IP(raw), nil
	case 6:
		if len(raw) != net.IPv6len {
			return nil, fmt.Errorf("unexpected ipv6 length %d", len(raw))
		}
		for i := 0; i < len(raw); i += 4 {
			reverseBytes(raw[i : i+4])
		}
		return net.IP(raw), nil
	default:
		return nil, fmt.Errorf("unsupported address family %d", family)
	}
}

func reverseBytes(in []byte) {
	for left, right := 0, len(in)-1; left < right; left, right = left+1, right-1 {
		in[left], in[right] = in[right], in[left]
	}
}

func mergeSocketProbes(a, b model.SocketProbe) model.SocketProbe {
	return model.SocketProbe{
		Loopback:    sortedUnique(append(append([]string{}, a.Loopback...), b.Loopback...)),
		NonLoopback: sortedUnique(append(append([]string{}, a.NonLoopback...), b.NonLoopback...)),
	}
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
