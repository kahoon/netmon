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
	defaultAlertHistoryInterval = 7 * 24 * time.Hour
)

const DefaultRPCSocketPath = defaultRPCSocketPath

type Config struct {
	DebugEvents bool

	MonitorInterface string
	ExpectedULA      string

	Topic          string
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
	AlertHistoryInterval  time.Duration
}

func LoadConfig() Config {
	return Config{
		MonitorInterface:     getenvDefault("MONITOR_IF", defaultMonitorInterface),
		ExpectedULA:          normalizeIPLiteral(getenvDefault("EXPECTED_ULA", "")),
		Topic:                mustEnv("NTFY_TOPIC"),
		NtfyHost:             getenvDefault("NTFY_HOST", defaultNtfyHost),
		NtfyResolver:         getenvDefault("NTFY_RESOLVER", defaultNtfyResolver),
		PiHolePassword:       getenvDefault("PIHOLE_PASSWORD", ""),
		RPCSocketPath:        getenvDefault("RPC_SOCKET_PATH", defaultRPCSocketPath),
		DebugEvents:          getenvBool("DEBUG_EVENTS", false),
		RuntimeStatsInterval: getenvDuration("RUNTIME_STATS_INTERVAL", defaultRuntimeStatsInterval),
		AlertHistoryInterval: getenvDuration("ALERT_HISTORY_INTERVAL", defaultAlertHistoryInterval),

		NetlinkDebounce:       defaultNetlinkDebounce,
		InterfacePollInterval: defaultInterfaceInterval,
		ListenerPollInterval:  defaultListenerInterval,
		UpstreamPollInterval:  defaultUpstreamInterval,
		UnboundPollInterval:   defaultUnboundInterval,
		PiHolePollInterval:    defaultPiHoleInterval,
		TailscalePollInterval: defaultTailscaleInterval,
		HTTPTimeout:           defaultHTTPTimeout,
		DNSProbeTimeout:       defaultDNSProbeTimeout,
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

	parsed, err := parseDuration(value)
	if err != nil {
		return def
	}
	return parsed
}

func parseDuration(value string) (time.Duration, error) {
	parsedDuration, parseErr := time.ParseDuration(value)
	if parseErr == nil {
		return parsedDuration, nil
	}

	days, ok := strings.CutSuffix(value, "d")
	if !ok {
		return 0, parseErr
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(days), 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(parsed * float64(24*time.Hour)), nil
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
