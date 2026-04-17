package config

import (
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMonitorInterface     = "eno1"
	defaultPublicIPResolver     = "208.67.222.222:53"
	defaultPublicIPName         = "myip.opendns.com"
	defaultNtfyHost             = "ntfy.sh"
	defaultNtfyResolver         = "9.9.9.9:53"
	defaultRPCSocketPath        = "/run/netmon/netmond.sock"
	defaultNetlinkDebounce      = 8 * time.Second
	defaultInterfaceInterval    = 10 * time.Minute
	defaultListenerInterval     = 10 * time.Minute
	defaultUpstreamInterval     = 5 * time.Minute
	defaultHTTPTimeout          = 10 * time.Second
	defaultDNSProbeTimeout      = 2 * time.Second
	defaultRuntimeStatsInterval = 7 * 24 * time.Hour
)

const DefaultRPCSocketPath = defaultRPCSocketPath

var (
	defaultRootServersV4 = []string{"192.203.230.10", "192.58.128.30"}
	defaultRootServersV6 = []string{"2001:500:a8::e", "2001:503:c27::2:30"}
)

type Config struct {
	Topic string

	MonitorInterface string
	ExpectedULA      string
	DebugEvents      bool

	RootServersV4    []string
	RootServersV6    []string
	PublicIPResolver string
	PublicIPName     string
	NtfyHost         string
	NtfyResolver     string
	RPCSocketPath    string

	NetlinkDebounce       time.Duration
	InterfacePollInterval time.Duration
	ListenerPollInterval  time.Duration
	UpstreamPollInterval  time.Duration
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
		RootServersV4:    getenvList("ROOT_DNS_V4", defaultRootServersV4),
		RootServersV6:    getenvList("ROOT_DNS_V6", defaultRootServersV6),
		PublicIPResolver: getenvDefault("PUBLIC_IP_RESOLVER", defaultPublicIPResolver),
		PublicIPName:     getenvDefault("PUBLIC_IP_NAME", defaultPublicIPName),
		NtfyHost:         getenvDefault("NTFY_HOST", defaultNtfyHost),
		NtfyResolver:     getenvDefault("NTFY_RESOLVER", defaultNtfyResolver),
		RPCSocketPath:    getenvDefault("RPC_SOCKET_PATH", defaultRPCSocketPath),

		NetlinkDebounce:       defaultNetlinkDebounce,
		InterfacePollInterval: defaultInterfaceInterval,
		ListenerPollInterval:  defaultListenerInterval,
		UpstreamPollInterval:  defaultUpstreamInterval,
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

func getenvList(key string, defaults []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return append([]string{}, defaults...)
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := normalizeIPLiteral(part)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}

	if len(out) == 0 {
		return append([]string{}, defaults...)
	}
	sort.Strings(out)
	return slicesCompact(out)
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

func slicesCompact(in []string) []string {
	if len(in) == 0 {
		return nil
	}

	out := in[:1]
	for _, value := range in[1:] {
		if value == out[len(out)-1] {
			continue
		}
		out = append(out, value)
	}
	return out
}
