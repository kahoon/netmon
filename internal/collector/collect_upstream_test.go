package collector

import (
	"net"
	"strings"
	"testing"

	"github.com/kahoon/netmon/internal/model"
	"github.com/miekg/dns"
)

func TestValidateRootNSAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		msg        *dns.Msg
		wantStatus model.DNSProbeStatus
		wantDetail string
	}{
		{
			name: "answer section root ns",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "e.root-servers.net."},
				},
			},
			wantStatus: model.DNSProbeStatusOK,
		},
		{
			name: "authority section root ns",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Ns: []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "j.root-servers.net."},
				},
			},
			wantStatus: model.DNSProbeStatusOK,
		},
		{name: "nil", msg: nil, wantStatus: model.DNSProbeStatusMalformed, wantDetail: "nil response"},
		{name: "missing qr", msg: &dns.Msg{}, wantStatus: model.DNSProbeStatusMalformed, wantDetail: "response missing QR bit"},
		{
			name:       "rcode refused",
			msg:        &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeRefused}},
			wantStatus: model.DNSProbeStatusRefused,
			wantDetail: "REFUSED",
		},
		{
			name:       "empty",
			msg:        &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
			wantStatus: model.DNSProbeStatusMalformed,
			wantDetail: "empty response",
		},
		{
			name: "non-root ns",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example.net."},
				},
			},
			wantStatus: model.DNSProbeStatusUnexpectedAnswer,
			wantDetail: "possible interception",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status, detail := validateRootNSAnswer(tt.msg)
			if status != tt.wantStatus {
				t.Fatalf("validateRootNSAnswer() status = %q, want %q", status, tt.wantStatus)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("validateRootNSAnswer() detail = %q, want substring %q", detail, tt.wantDetail)
			}
		})
	}
}

func TestValidateExpectedAddressAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		msg        *dns.Msg
		qtype      uint16
		expected   string
		wantStatus model.DNSProbeStatus
		wantDetail string
	}{
		{
			name: "a answer ok",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: "e.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 203, 230, 10}},
				},
			},
			qtype:      dns.TypeA,
			expected:   "192.203.230.10",
			wantStatus: model.DNSProbeStatusOK,
		},
		{
			name: "aaaa answer ok",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Name: "j.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: mustIP(t, "2001:503:c27::2:30")},
				},
			},
			qtype:      dns.TypeAAAA,
			expected:   "2001:503:c27::2:30",
			wantStatus: model.DNSProbeStatusOK,
		},
		{
			name: "missing expected",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: "e.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 0, 2, 10}},
				},
			},
			qtype:      dns.TypeA,
			expected:   "192.203.230.10",
			wantStatus: model.DNSProbeStatusUnexpectedAnswer,
			wantDetail: "expected 192.203.230.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status, detail := validateExpectedAddressAnswer(tt.msg, tt.qtype, tt.expected)
			if status != tt.wantStatus {
				t.Fatalf("validateExpectedAddressAnswer() status = %q, want %q", status, tt.wantStatus)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("validateExpectedAddressAnswer() detail = %q, want substring %q", detail, tt.wantDetail)
			}
		})
	}
}

func TestExtractObservedIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		msg        *dns.Msg
		qtype      uint16
		want       string
		wantDetail string
	}{
		{
			name: "opendns ipv4",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: "myip.opendns.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{198, 51, 100, 42}},
				},
			},
			qtype: dns.TypeA,
			want:  "198.51.100.42",
		},
		{
			name: "google txt ipv6",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.TXT{Hdr: dns.RR_Header{Name: "o-o.myaddr.l.google.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"2001:db8::42"}},
				},
			},
			qtype: dns.TypeTXT,
			want:  "2001:db8::42",
		},
		{
			name: "txt wrong family",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.TXT{Hdr: dns.RR_Header{Name: "o-o.myaddr.l.google.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"74.125.19.187"}},
				},
			},
			qtype:      dns.TypeTXT,
			wantDetail: "no public IP answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			family := 4
			if strings.Contains(tt.want, ":") || tt.name == "txt wrong family" {
				family = 6
			}

			got, detail := extractObservedIP(tt.msg, tt.qtype, family)
			if got != tt.want {
				t.Fatalf("extractObservedIP() = %q, want %q", got, tt.want)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("extractObservedIP() detail = %q, want substring %q", detail, tt.wantDetail)
			}
		})
	}
}

func TestValidateDNSSECPositiveAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		msg        *dns.Msg
		wantStatus model.DNSSECProbeStatus
		wantRcode  string
		wantAD     bool
		wantDetail string
	}{
		{
			name: "ok",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess, AuthenticatedData: true},
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: dnssecPositive, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{104, 16, 253, 183}},
				},
			},
			wantStatus: model.DNSSECProbeStatusOK,
			wantRcode:  "NOERROR",
			wantAD:     true,
		},
		{
			name: "missing ad",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: dnssecPositive, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{104, 16, 253, 183}},
				},
			},
			wantStatus: model.DNSSECProbeStatusUnexpectedFailure,
			wantRcode:  "NOERROR",
			wantDetail: "missing AD bit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status, rcode, ad, detail := validateDNSSECPositiveAnswer(tt.msg)
			if status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", status, tt.wantStatus)
			}
			if rcode != tt.wantRcode {
				t.Fatalf("rcode = %q, want %q", rcode, tt.wantRcode)
			}
			if ad != tt.wantAD {
				t.Fatalf("ad = %t, want %t", ad, tt.wantAD)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("detail = %q, want substring %q", detail, tt.wantDetail)
			}
		})
	}
}

func TestValidateDNSSECNegativeAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		msg        *dns.Msg
		wantStatus model.DNSSECProbeStatus
		wantRcode  string
		wantDetail string
	}{
		{
			name: "servfail ok",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeServerFailure},
			},
			wantStatus: model.DNSSECProbeStatusOK,
			wantRcode:  "SERVFAIL",
		},
		{
			name: "unexpected success",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			},
			wantStatus: model.DNSSECProbeStatusUnexpectedSuccess,
			wantRcode:  "NOERROR",
			wantDetail: "expected SERVFAIL, got NOERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status, rcode, _, detail := validateDNSSECNegativeAnswer(tt.msg)
			if status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", status, tt.wantStatus)
			}
			if rcode != tt.wantRcode {
				t.Fatalf("rcode = %q, want %q", rcode, tt.wantRcode)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("detail = %q, want substring %q", detail, tt.wantDetail)
			}
		})
	}
}

func mustIP(t *testing.T, value string) []byte {
	t.Helper()
	return net.ParseIP(value)
}
