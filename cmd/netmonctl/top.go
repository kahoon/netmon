package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/charmbracelet/lipgloss"
	netmonv1 "github.com/kahoon/netmon/proto/netmon/v1"
	"golang.org/x/term"
)

var (
	topStyleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Bold(true)
	topStyleWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	topStyleCrit    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	topStyleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	topStyleSection = lipgloss.NewStyle().Bold(true)
)

type topStore struct {
	mu         sync.Mutex
	status     *netmonv1.GetStatusResponse
	state      *netmonv1.GetStateResponse
	info       *netmonv1.GetInfoResponse
	lastUpdate time.Time
}

func (s *topStore) setStatus(v *netmonv1.GetStatusResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = v
	s.lastUpdate = time.Now()
}

func (s *topStore) setState(v *netmonv1.GetStateResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = v
	s.lastUpdate = time.Now()
}

func (s *topStore) setInfo(v *netmonv1.GetInfoResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info = v
}

func (s *topStore) get() (*netmonv1.GetStatusResponse, *netmonv1.GetStateResponse, *netmonv1.GetInfoResponse, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.state, s.info, s.lastUpdate
}

func runTop(spec commandSpec, args []string) {
	cmd := newCommandContextWithTimeout(spec, args, forever)
	defer cmd.cancel()

	fmt.Print("\033[?1049h\033[?25l") // enter alternate screen, hide cursor
	defer fmt.Print("\033[?1049l\033[?25h")

	fd := int(os.Stdin.Fd())
	if old, err := term.MakeRaw(fd); err == nil {
		defer term.Restore(fd, old)
	}

	store := &topStore{}

	// Seed initial data.
	if resp, err := cmd.client.GetStatus(cmd.ctx, connect.NewRequest(&netmonv1.GetStatusRequest{})); err == nil {
		store.setStatus(resp.Msg)
	}
	if resp, err := cmd.client.GetState(cmd.ctx, connect.NewRequest(&netmonv1.GetStateRequest{})); err == nil {
		store.setState(resp.Msg)
	}
	if resp, err := cmd.client.GetInfo(cmd.ctx, connect.NewRequest(&netmonv1.GetInfoRequest{})); err == nil {
		store.setInfo(resp.Msg)
	}

	// Stream status updates in the background.
	go func() {
		stream, err := cmd.client.WatchStatus(cmd.ctx, connect.NewRequest(&netmonv1.WatchStatusRequest{}))
		if err != nil {
			return
		}
		defer stream.Close()
		for stream.Receive() {
			store.setStatus(stream.Msg().GetStatus())
		}
	}()

	// Read keypresses one byte at a time.
	keys := make(chan byte, 4)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				keys <- buf[0]
			}
			if err != nil {
				return
			}
		}
	}()

	fetchState := func() {
		if resp, err := cmd.client.GetState(cmd.ctx, connect.NewRequest(&netmonv1.GetStateRequest{})); err == nil {
			store.setState(resp.Msg)
		}
	}

	draw := func() {
		status, state, info, lastUpdate := store.get()
		w, _, err := term.GetSize(fd)
		if err != nil || w < 40 {
			w = 80
		}
		fmt.Print("\033[H\033[2J")
		fmt.Print(renderTop(status, state, info, lastUpdate, w))
	}

	draw()

	stateTicker := time.NewTicker(30 * time.Second)
	defer stateTicker.Stop()
	renderTicker := time.NewTicker(time.Second)
	defer renderTicker.Stop()

	for {
		select {
		case <-cmd.ctx.Done():
			return
		case key := <-keys:
			switch key {
			case 'q', 'Q', 3: // 3 = Ctrl+C
				return
			case 'r', 'R':
				_, _ = cmd.client.Refresh(cmd.ctx, connect.NewRequest(&netmonv1.RefreshRequest{
					Scope: netmonv1.RefreshScope_REFRESH_SCOPE_ALL,
				}))
				fetchState()
				draw()
			}
		case <-stateTicker.C:
			fetchState()
		case <-renderTicker.C:
			draw()
		}
	}
}

func renderTop(status *netmonv1.GetStatusResponse, state *netmonv1.GetStateResponse, info *netmonv1.GetInfoResponse, lastUpdate time.Time, width int) string {
	var b strings.Builder

	b.WriteString(renderTopHeader(status, info, lastUpdate, width))
	b.WriteString("\r\n\r\n") // \r required: MakeRaw disables ONLCR so \n alone won't reset column

	leftWidth := width/2 - 1
	rightWidth := width - leftWidth - 3

	left := renderChecksPanel(status, leftWidth)
	right := renderStatePanel(state, rightWidth)

	b.WriteString(joinColumns(left, right, leftWidth))
	return b.String()
}

// joinColumns zips two multi-line column strings side by side. Each line of
// the left column is padded to exactly leftWidth visible characters before the
// separator is appended, avoiding ANSI-width issues from lipgloss block layout.
func joinColumns(left, right string, leftWidth int) string {
	leftLines := strings.Split(strings.TrimRight(left, "\n"), "\n")
	rightLines := strings.Split(strings.TrimRight(right, "\n"), "\n")

	count := max(len(leftLines), len(rightLines))

	var b strings.Builder
	for i := range count {
		var l, r string
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		// Pad the left line to leftWidth visible characters.
		pad := leftWidth - lipgloss.Width(l)
		if pad > 0 {
			l += strings.Repeat(" ", pad)
		}
		b.WriteString(l)
		b.WriteString("  ")
		b.WriteString(r)
		b.WriteString("\r\n") // \r required: MakeRaw disables ONLCR so \n alone won't reset column
	}
	return b.String()
}

func renderTopHeader(status *netmonv1.GetStatusResponse, info *netmonv1.GetInfoResponse, lastUpdate time.Time, width int) string {
	badge := topStyleDim.Render("● connecting...")

	if status != nil {
		switch status.GetOverallSeverity() {
		case netmonv1.Severity_SEVERITY_OK:
			badge = topStyleOK.Render("● OK")
		case netmonv1.Severity_SEVERITY_WARN:
			badge = topStyleWarn.Render("● WARN")
		case netmonv1.Severity_SEVERITY_CRIT:
			badge = topStyleCrit.Render("● CRIT")
		default:
			badge = topStyleDim.Render("● ?")
		}

		var ips []string
		if ip := status.GetPublicIpv4(); ip != "" {
			ips = append(ips, ip)
		}
		if ip := status.GetPublicIpv6(); ip != "" {
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			badge += topStyleDim.Render("   " + strings.Join(ips, "  "))
		}
	}

	// Right side: version + uptime + update age + keybinds
	var metaParts []string
	if info != nil {
		if v := info.GetVersion(); v != "" {
			metaParts = append(metaParts, v)
		}
		if ts := info.GetStartedAtUnix(); ts > 0 {
			uptime := time.Since(time.Unix(ts, 0))
			metaParts = append(metaParts, "up "+topFormatAge(uptime))
		}
	}
	if !lastUpdate.IsZero() {
		metaParts = append(metaParts, "updated "+topFormatAge(time.Since(lastUpdate))+" ago")
	}
	metaParts = append(metaParts, "[r]efresh  [q]uit")
	right := topStyleDim.Render(strings.Join(metaParts, "   "))

	// Build content and pad to exactly width visible characters, then apply
	// background. We avoid passing pre-styled ANSI strings to lipgloss's
	// Width/Padding renderer because inner reset codes fight the outer style.
	content := " " + badge + "   " + right + " "
	pad := width - lipgloss.Width(content)
	if pad > 0 {
		// Insert padding between badge and right so the right side stays flush.
		content = " " + badge + strings.Repeat(" ", pad+3) + right + " "
	}
	return lipgloss.NewStyle().Background(lipgloss.Color("235")).Render(content)
}

func renderChecksPanel(status *netmonv1.GetStatusResponse, width int) string {
	var b strings.Builder

	b.WriteString(topStyleSection.Render("CHECKS"))
	b.WriteByte('\n')
	b.WriteString(topStyleDim.Render(strings.Repeat("─", width)))
	b.WriteByte('\n')

	if status == nil {
		b.WriteString(topStyleDim.Render("(no data)"))
		return b.String()
	}

	nameWidth := width - 8 // icon + spaces + severity label
	if nameWidth < 8 {
		nameWidth = 8
	}

	for _, check := range status.GetChecks() {
		icon := topSeverityIcon(check.GetSeverity())
		name := check.GetName()
		if len(name) > nameWidth {
			name = name[:nameWidth-1] + "…"
		}

		var sevStr string
		switch check.GetSeverity() {
		case netmonv1.Severity_SEVERITY_WARN:
			sevStr = topStyleWarn.Render("WARN")
		case netmonv1.Severity_SEVERITY_CRIT:
			sevStr = topStyleCrit.Render("CRIT")
		default:
			sevStr = topStyleDim.Render("ok")
		}

		b.WriteString(icon + " " + fmt.Sprintf("%-*s", nameWidth, name) + " " + sevStr)
		b.WriteByte('\n')

		if check.GetSeverity() != netmonv1.Severity_SEVERITY_OK {
			if summary := check.GetSummary(); summary != "" {
				b.WriteString(topStyleDim.Render("  " + summary))
				b.WriteByte('\n')
			}
		}
	}

	return b.String()
}

const topLabelWidth = 11

func renderStatePanel(state *netmonv1.GetStateResponse, width int) string {
	if state == nil {
		return topStyleDim.Render("(no data)")
	}

	var b strings.Builder
	b.WriteString(renderTopPiHole(state.GetPihole(), width))
	b.WriteString("\n\n")
	b.WriteString(renderTopTailscale(state.GetTailscale(), width))
	return b.String()
}

func renderTopPiHole(p *netmonv1.PiHoleState, width int) string {
	var b strings.Builder

	b.WriteString(topStyleSection.Render("PI-HOLE"))
	b.WriteByte('\n')
	b.WriteString(topStyleDim.Render(strings.Repeat("─", width)))
	b.WriteByte('\n')

	if p == nil {
		b.WriteString(topStyleDim.Render("(no data)"))
		return b.String()
	}

	// Blocking + FTL version
	blocking := defaultString(p.GetStatus().GetBlocking(), "(unknown)")
	var blockStr string
	switch blocking {
	case "enabled":
		blockStr = topStyleOK.Render("enabled")
	case "disabled":
		blockStr = topStyleCrit.Render("disabled")
	default:
		blockStr = topStyleDim.Render(blocking)
	}
	if v := p.GetStatus().GetFtlVersion(); v != "" {
		blockStr += topStyleDim.Render("  " + v)
	}
	b.WriteString(topRow(topLabelWidth, "Blocking", blockStr))
	b.WriteByte('\n')

	// DNS probes
	b.WriteString(topRow(topLabelWidth, "DNS v4", topProbeCompact(p.GetDnsV4())))
	b.WriteByte('\n')
	b.WriteString(topRow(topLabelWidth, "DNS v6", topProbeCompact(p.GetDnsV6())))
	b.WriteByte('\n')

	// Latency
	b.WriteString(topRow(topLabelWidth, "Latency", topLatencyCompact("v4", p.GetLatencyIpv4())))
	b.WriteByte('\n')
	b.WriteString(topRow(topLabelWidth, "", topLatencyCompact("v6", p.GetLatencyIpv6())))
	b.WriteByte('\n')

	// Upstreams
	var upStr string
	if u := p.GetUpstreams(); u != nil {
		if u.GetMatchesExpected() {
			upStr = topStyleOK.Render("✓") + topStyleDim.Render(" expected")
		} else if d := u.GetDetail(); d != "" {
			upStr = topStyleCrit.Render("✗") + topStyleDim.Render(" "+d)
		} else {
			upStr = topStyleWarn.Render("✗") + topStyleDim.Render(" mismatch")
		}
	}
	b.WriteString(topRow(topLabelWidth, "Upstreams", upStr))
	b.WriteByte('\n')

	// Gravity
	if g := p.GetGravity(); g != nil {
		gStr := topFormatCount(g.GetDomainsBlocked()) + topStyleDim.Render(" domains")
		if ts := g.GetLastUpdated(); ts != nil {
			gStr += topStyleDim.Render("  " + topFormatAge(time.Since(ts.AsTime())) + " ago")
		}
		if g.GetStale() {
			gStr += "  " + topStyleWarn.Render("stale")
		}
		b.WriteString(topRow(topLabelWidth, "Gravity", gStr))
		b.WriteByte('\n')
	}

	// Queries
	if c := p.GetCounters(); c != nil && c.GetQueriesTotal() > 0 {
		total := c.GetQueriesTotal()
		blocked := c.GetQueriesBlocked()
		pct := blocked * 100 / total
		b.WriteString(topRow(topLabelWidth, "Queries",
			fmt.Sprintf("%s total  %s blocked  %d%%",
				topFormatCount(total), topFormatCount(blocked), pct)))
		b.WriteByte('\n')
	}

	return b.String()
}

func renderTopTailscale(ts *netmonv1.TailscaleState, width int) string {
	var b strings.Builder

	b.WriteString(topStyleSection.Render("TAILSCALE"))
	b.WriteByte('\n')
	b.WriteString(topStyleDim.Render(strings.Repeat("─", width)))
	b.WriteByte('\n')

	if ts == nil {
		b.WriteString(topStyleDim.Render("(no data)"))
		return b.String()
	}

	st := ts.GetStatus()

	// Connection state
	var connStr string
	if st.GetConnected() {
		connStr = topStyleOK.Render("connected")
	} else {
		connStr = topStyleCrit.Render("disconnected")
	}
	if state := st.GetBackendState(); state != "" {
		connStr += topStyleDim.Render("  " + strings.ToLower(state))
	}
	b.WriteString(topRow(topLabelWidth, "State", connStr))
	b.WriteByte('\n')

	// Tailscale address
	if addr := ts.GetAddresses(); addr.GetIpv4() != "" {
		b.WriteString(topRow(topLabelWidth, "Address", addr.GetIpv4()))
		b.WriteByte('\n')
	}

	// Peers
	if p := ts.GetPeers(); p.GetTotal() > 0 {
		b.WriteString(topRow(topLabelWidth, "Peers",
			fmt.Sprintf("%d total  %d online  %d direct  %d relay",
				p.GetTotal(), p.GetOnline(), p.GetDirect(), p.GetRelay())))
		b.WriteByte('\n')
	}

	// Exit node
	if r := ts.GetRoles(); r.GetAdvertisesExitNode() {
		b.WriteString(topRow(topLabelWidth, "Exit node", topStyleOK.Render("advertising")))
		b.WriteByte('\n')
	}

	return b.String()
}

func topRow(labelWidth int, label, value string) string {
	return lipgloss.NewStyle().Width(labelWidth).Foreground(lipgloss.Color("248")).Render(label) + " " + value
}

func topSeverityIcon(severity netmonv1.Severity) string {
	switch severity {
	case netmonv1.Severity_SEVERITY_OK:
		return topStyleOK.Render("✓")
	case netmonv1.Severity_SEVERITY_WARN:
		return topStyleWarn.Render("!")
	case netmonv1.Severity_SEVERITY_CRIT:
		return topStyleCrit.Render("✗")
	default:
		return topStyleDim.Render("?")
	}
}

func topProbeCompact(probe *netmonv1.DnsProbeResult) string {
	if probe == nil {
		return topStyleDim.Render("(unknown)")
	}
	if probe.GetStatus() == "ok" {
		s := topStyleOK.Render("ok")
		if lat := probe.GetLatency(); lat != nil {
			s += topStyleDim.Render("  " + lat.AsDuration().String())
		}
		return s
	}
	return topStyleCrit.Render(strings.ToUpper(strings.ReplaceAll(probe.GetStatus(), "_", " ")))
}

func topLatencyCompact(family string, w *netmonv1.DnsLatencyWindow) string {
	prefix := topStyleDim.Render(family)
	if w == nil || w.GetSamples() == 0 {
		return prefix + topStyleDim.Render(" no data")
	}
	avg := ""
	if a := w.GetAverage(); a != nil {
		avg = a.AsDuration().String()
	}
	return prefix + " avg " + avg + "  " + topTrendArrow(w.GetTrend())
}

func topTrendArrow(trend string) string {
	switch trend {
	case "rising":
		return topStyleWarn.Render("↑ rising")
	case "falling":
		return topStyleOK.Render("↓ falling")
	case "stable":
		return topStyleDim.Render("→ stable")
	case "unknown":
		return topStyleDim.Render("→ calculating...")
	default:
		return topStyleDim.Render("?")
	}
}

func topFormatAge(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func topFormatCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}
