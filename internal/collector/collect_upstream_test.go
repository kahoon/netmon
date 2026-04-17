package collector

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestValidateRootNSAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     *dns.Msg
		wantErr string
	}{
		{
			name: "answer section root ns",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "a.root-servers.net."},
				},
			},
		},
		{
			name: "authority section root ns",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Ns: []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "b.root-servers.net."},
				},
			},
		},
		{name: "nil", msg: nil, wantErr: "nil response"},
		{name: "missing qr", msg: &dns.Msg{}, wantErr: "response missing QR bit"},
		{
			name:    "rcode",
			msg:     &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeNameError}},
			wantErr: "dns rcode=3",
		},
		{
			name:    "empty",
			msg:     &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
			wantErr: "empty response",
		},
		{
			name: "non-root ns",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example.net."},
				},
			},
			wantErr: "possible interception",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateRootNSAnswer(tt.msg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRootNSAnswer() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRootNSAnswer() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestExtractPublicIPv4(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     *dns.Msg
		want    string
		wantErr string
	}{
		{
			name: "ok",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Name: "myip.opendns.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{198, 51, 100, 42}},
				},
			},
			want: "198.51.100.42",
		},
		{name: "nil", msg: nil, wantErr: "nil response"},
		{name: "missing qr", msg: &dns.Msg{}, wantErr: "response missing QR bit"},
		{
			name:    "rcode",
			msg:     &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeServerFailure}},
			wantErr: "dns rcode=2",
		},
		{
			name:    "empty",
			msg:     &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}},
			wantErr: "no IPv4 answers",
		},
		{
			name: "no a records",
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Name: "myip.opendns.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}},
				},
			},
			wantErr: "no IPv4 answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := extractPublicIPv4(tt.msg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("extractPublicIPv4() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("extractPublicIPv4() = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("extractPublicIPv4() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
