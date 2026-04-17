package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/kahoon/netmon/internal/config"
	"github.com/kahoon/netmon/internal/model"
)

type Notification struct {
	Severity model.Severity
	Title    string
	Body     string
}

type NtfyNotifier struct {
	host   string
	topic  string
	client *http.Client
}

func NewNtfyNotifier(cfg config.Config) *NtfyNotifier {
	resolverAddress := model.EnsurePort(cfg.NtfyResolver, "53")
	resolverDialer := &net.Dialer{Timeout: cfg.DNSProbeTimeout}
	fallbackResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return resolverDialer.DialContext(ctx, "udp", resolverAddress)
		},
	}

	baseDialer := &net.Dialer{Timeout: cfg.HTTPTimeout}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: cfg.NtfyHost},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}

			if !strings.EqualFold(host, cfg.NtfyHost) {
				return baseDialer.DialContext(ctx, network, address)
			}

			ips, err := fallbackResolver.LookupIP(ctx, "ip", cfg.NtfyHost)
			if err != nil {
				return nil, err
			}

			var dialErrors []string
			for _, ip := range ips {
				target := net.JoinHostPort(ip.String(), port)
				conn, err := baseDialer.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				dialErrors = append(dialErrors, err.Error())
			}

			if len(dialErrors) == 0 {
				return nil, fmt.Errorf("no IPs found for %s", cfg.NtfyHost)
			}
			return nil, fmt.Errorf("dial %s via fallback resolver: %s", cfg.NtfyHost, strings.Join(dialErrors, "; "))
		},
	}

	return &NtfyNotifier{
		host:  cfg.NtfyHost,
		topic: cfg.Topic,
		client: &http.Client{
			Timeout:   cfg.HTTPTimeout,
			Transport: transport,
		},
	}
}

func (n *NtfyNotifier) Send(ctx context.Context, note Notification) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://"+n.host+"/"+n.topic,
		strings.NewReader(note.Body),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Title", note.Title)
	req.Header.Set("Priority", note.Severity.Priority())
	req.Header.Set("Tags", note.Severity.Tags())

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned %s", resp.Status)
	}

	return nil
}

func BuildChangeNotification(cfg config.Config, reason string, previous, current model.SystemState, previousChecks, currentChecks model.CheckSet) *Notification {
	lines := changedCheckLines(previousChecks, currentChecks)
	if line := publicIPv4ChangeLine(previous.Upstream.PublicIPv4, current.Upstream.PublicIPv4); line != "" {
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil
	}

	severity := model.CurrentOverallSeverity(currentChecks)
	bodyLines := []string{
		"reason: " + reason,
		"severity: " + severity.String(),
		"changed:",
	}
	for _, line := range lines {
		bodyLines = append(bodyLines, "- "+line)
	}

	return &Notification{
		Severity: severity,
		Title:    fmt.Sprintf("%s netmon %s", severity.String(), cfg.MonitorInterface),
		Body:     strings.Join(bodyLines, "\n"),
	}
}

func BuildErrorNotification(cfg config.Config, reason string, err error) Notification {
	severity := model.SeverityWarn
	lines := []string{
		"reason: " + reason,
		"severity: " + severity.String(),
		"changed:",
		"- monitor refresh failed: " + err.Error(),
	}

	return Notification{
		Severity: severity,
		Title:    fmt.Sprintf("%s netmon %s", severity.String(), cfg.MonitorInterface),
		Body:     strings.Join(lines, "\n"),
	}
}

func changedCheckLines(previousChecks, currentChecks model.CheckSet) []string {
	lines := make([]string, 0, len(model.CheckOrder()))
	for _, key := range model.CheckOrder() {
		prev := previousChecks[key]
		curr := currentChecks[key]
		if prev.Equal(curr) {
			continue
		}

		switch {
		case curr.Severity == model.SeverityOK && prev.Severity != model.SeverityOK:
			lines = append(lines, curr.Label+" recovered")
		case curr.Severity != model.SeverityOK:
			lines = append(lines, curr.Summary)
		}
	}

	return lines
}

func publicIPv4ChangeLine(previous, current model.PublicIPResult) string {
	if previous.IPv4 == "" || current.IPv4 == "" || previous.IPv4 == current.IPv4 {
		return ""
	}

	return fmt.Sprintf("public IPv4 changed %s -> %s", previous.IPv4, current.IPv4)
}

func summarizeChecks(checks model.CheckSet) string {
	var parts []string
	for _, key := range model.CheckOrder() {
		result, ok := checks[key]
		if !ok || result.Severity == model.SeverityOK {
			continue
		}
		parts = append(parts, result.Summary)
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "healthy"
	}
	return strings.Join(parts, "; ")
}
