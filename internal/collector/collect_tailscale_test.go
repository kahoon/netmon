package collector

import (
	"context"
	"testing"
)

type fakeTailscaleRunner struct {
	status []byte
	prefs  []byte
	err    error
}

func (f fakeTailscaleRunner) Status(context.Context) ([]byte, error) {
	return f.status, f.err
}

func (f fakeTailscaleRunner) Prefs(context.Context) ([]byte, error) {
	return f.prefs, f.err
}

func TestTailscaleCollectorCollect(t *testing.T) {
	collector := TailscaleCollector{
		Runner: fakeTailscaleRunner{
			status: []byte(`{
				"Version":"1.96.4",
				"BackendState":"Running",
				"HaveNodeKey":true,
				"AuthURL":"",
				"TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"],
				"MagicDNSSuffix":"example.ts.net",
				"CurrentTailnet":{"Name":"user@example.com","MagicDNSSuffix":"example.ts.net"},
				"Self":{"HostName":"testhost","DNSName":"testhost.example.ts.net.","TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"],"Online":true,"Relay":"tor"},
				"Peer":{
					"one":{"Online":true,"Relay":"tor"},
					"two":{"Online":true,"Relay":"tor","Active":true,"CurAddr":"198.51.100.1:59743","InMagicSock":true,"InEngine":true},
					"three":{"Online":false,"Relay":""}
				}
			}`),
			prefs: []byte(`{
				"WantRunning":true,
				"LoggedOut":false,
				"AdvertiseRoutes":["192.168.1.0/24","0.0.0.0/0","::/0"]
			}`),
		},
	}

	state := collector.Collect(context.Background())
	if !state.Status.Connected {
		t.Fatal("Status.Connected = false, want true")
	}
	if got, want := state.Addresses.IPv4, "100.64.0.1"; got != want {
		t.Fatalf("Addresses.IPv4 = %q, want %q", got, want)
	}
	if got, want := state.Peers.Total, uint64(3); got != want {
		t.Fatalf("Peers.Total = %d, want %d", got, want)
	}
	if got, want := state.Peers.Online, uint64(2); got != want {
		t.Fatalf("Peers.Online = %d, want %d", got, want)
	}
	if got, want := state.Peers.Direct, uint64(1); got != want {
		t.Fatalf("Peers.Direct = %d, want %d", got, want)
	}
	if got, want := state.Peers.Relay, uint64(1); got != want {
		t.Fatalf("Peers.Relay = %d, want %d", got, want)
	}
	if !state.Roles.AdvertisesExitNode {
		t.Fatal("Roles.AdvertisesExitNode = false, want true")
	}
	if got, want := len(state.Roles.AdvertisedRoutes), 3; got != want {
		t.Fatalf("len(Roles.AdvertisedRoutes) = %d, want %d", got, want)
	}
}
