package collector

import (
	"strings"
	"testing"

	"github.com/kahoon/netmon/internal/model"
	"github.com/miekg/dns"
)

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
