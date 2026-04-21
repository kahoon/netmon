package config

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMonitorInterface     = "eno1"
	defaultNtfyHost             = "ntfy.sh"
	defaultNtfyResolver         = "9.9.9.9:53"
	defaultRPCSocketPath        = "/run/netmon/netmond.sock"
	defaultNetlinkDebounce      = 8 * time.Second
	defaultInterfaceInterval    = 10 * time.Minute
	defaultListenerInterval     = 10 * time.Minute
	defaultUpstreamInterval     = 5 * time.Minute
	defaultUnboundInterval      = 5 * time.Minute
	defaultPiHoleInterval       = 5 * time.Minute
	defaultTailscaleInterval    = 5 * time.Minute
	defaultHTTPTimeout          = 10 * time.Second
	defaultDNSProbeTimeout      = 2 * time.Second
	defaultRuntimeStatsInterval = 7 * 24 * time.Hour
)

const DefaultRPCSocketPath = defaultRPCSocketPath

type Config struct {
	Topic string

	MonitorInterface string
	ExpectedULA      string
	DebugEvents      bool

	NtfyHost       string
	NtfyResolver   string
	RPCSocketPath  string
	PiHolePassword string

	NetlinkDebounce       time.Duration
	InterfacePollInterval time.Duration
	ListenerPollInterval  time.Duration
	UpstreamPollInterval  time.Duration
	UnboundPollInterval   time.Duration
	PiHolePollInterval    time.Duration
	TailscalePollInterval time.Duration
	HTTPTimeout           time.Duration
	DNSProbeTimeout       time.Duration
	RuntimeStatsInterval  time.Duration
}

func LoadConfig() Config {
	return Config{
		Topic:            mustEnv("NTFY_TOPIC"),
		MonitorInterface: getenvDefault("MONITOR_IF", defaultMonitorInterface),
		ExpectedULA:      normalizeIPLiteral(getenvDefault("EXPECTED_ULA", "")),
		DebugEvents:      getenvBool("DEBUG_EVENTS", false),
		NtfyHost:         getenvDefault("NTFY_HOST", defaultNtfyHost),
		NtfyResolver:     getenvDefault("NTFY_RESOLVER", defaultNtfyResolver),
		RPCSocketPath:    getenvDefault("RPC_SOCKET_PATH", defaultRPCSocketPath),
		PiHolePassword:   getenvDefault("PIHOLE_PASSWORD", ""),

		NetlinkDebounce:       defaultNetlinkDebounce,
		InterfacePollInterval: defaultInterfaceInterval,
		ListenerPollInterval:  defaultListenerInterval,
		UpstreamPollInterval:  defaultUpstreamInterval,
		UnboundPollInterval:   getenvDuration("UNBOUND_POLL_INTERVAL", defaultUnboundInterval),
		PiHolePollInterval:    getenvDuration("PIHOLE_POLL_INTERVAL", defaultPiHoleInterval),
		TailscalePollInterval: defaultTailscaleInterval,
		HTTPTimeout:           defaultHTTPTimeout,
		DNSProbeTimeout:       defaultDNSProbeTimeout,
		RuntimeStatsInterval:  getenvDuration("RUNTIME_STATS_INTERVAL", defaultRuntimeStatsInterval),
	}
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s not set", key)
	}
	return value
}

func getenvDefault(key, def string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	return value
}

func getenvBool(key string, def bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return def
	}
	return parsed
}

func getenvDuration(key string, def time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return def
	}
	return parsed
}

func normalizeIPLiteral(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	if ip16 := ip.To16(); ip16 != nil {
		return ip16.String()
	}
	return ip.String()
}
