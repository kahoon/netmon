package collector

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestReadProcSocketFileIPv4ClassifiesLoopbackAndNonLoopback(t *testing.T) {
	t.Parallel()

	path := writeProcSocketFixture(t,
		"  sl  local_address rem_address   st",
		procSocketLine(0, net.IPv4(127, 0, 0, 1), 53, tcpListenState, 4),
		procSocketLine(1, net.IPv4(192, 168, 1, 10), 53, tcpListenState, 4),
		procSocketLine(2, net.IPv4(192, 168, 1, 11), 5353, tcpListenState, 4),
		procSocketLine(3, net.IPv4(192, 168, 1, 12), 53, "01", 4),
	)

	probe, err := readProcSocketFile(path, 53, 4, tcpListenState)
	if err != nil {
		t.Fatalf("readProcSocketFile() error = %v", err)
	}

	if want := []string{"127.0.0.1:53"}; !slices.Equal(probe.Loopback, want) {
		t.Fatalf("Loopback = %v, want %v", probe.Loopback, want)
	}
	if want := []string{"192.168.1.10:53"}; !slices.Equal(probe.NonLoopback, want) {
		t.Fatalf("NonLoopback = %v, want %v", probe.NonLoopback, want)
	}
}

func TestReadProcSocketFileIPv6ClassifiesLoopbackAndNonLoopback(t *testing.T) {
	t.Parallel()

	path := writeProcSocketFixture(t,
		"  sl  local_address rem_address   st",
		procSocketLine(0, net.ParseIP("::1"), 5335, udpListenState, 6),
		procSocketLine(1, net.ParseIP("2001:db8::15"), 5335, udpListenState, 6),
	)

	probe, err := readProcSocketFile(path, 5335, 6, udpListenState)
	if err != nil {
		t.Fatalf("readProcSocketFile() error = %v", err)
	}

	if want := []string{"[::1]:5335"}; !slices.Equal(probe.Loopback, want) {
		t.Fatalf("Loopback = %v, want %v", probe.Loopback, want)
	}
	if want := []string{"[2001:db8::15]:5335"}; !slices.Equal(probe.NonLoopback, want) {
		t.Fatalf("NonLoopback = %v, want %v", probe.NonLoopback, want)
	}
}

func TestParseProcIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hexAddr string
		family  int
		want    string
		wantErr string
	}{
		{name: "ipv4", hexAddr: "0100007F", family: 4, want: "127.0.0.1"},
		{name: "ipv6", hexAddr: "00000000000000000000000001000000", family: 6, want: "::1"},
		{name: "bad family", hexAddr: "0100007F", family: 5, wantErr: "unsupported address family"},
		{name: "bad hex", hexAddr: "nope", family: 4, wantErr: "decode address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseProcIP(tt.hexAddr, tt.family)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseProcIP() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProcIP() error = %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("parseProcIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func writeProcSocketFixture(t *testing.T, lines ...string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "proc-net")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func procSocketLine(slot int, ip net.IP, port int, state string, family int) string {
	return strings.Join([]string{
		strconv.Itoa(slot) + ":",
		encodeProcIP(ip, family) + ":" + strings.ToUpper(strconv.FormatInt(int64(port), 16)),
		"00000000:0000",
		state,
	}, " ")
}

func encodeProcIP(ip net.IP, family int) string {
	switch family {
	case 4:
		raw := append([]byte{}, ip.To4()...)
		reverseBytes(raw)
		return strings.ToUpper(hexString(raw))
	case 6:
		raw := append([]byte{}, ip.To16()...)
		for i := 0; i < len(raw); i += 4 {
			reverseBytes(raw[i : i+4])
		}
		return strings.ToUpper(hexString(raw))
	default:
		panic("unsupported family")
	}
}

func hexString(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}
