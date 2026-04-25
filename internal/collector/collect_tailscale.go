package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/kahoon/netmon/internal/model"
)

type TailscaleRunner interface {
	Status(context.Context) ([]byte, error)
	Prefs(context.Context) ([]byte, error)
}

type TailscaleCollector struct {
	Runner TailscaleRunner
}

func NewTailscaleCollector() TailscaleCollector {
	return TailscaleCollector{
		Runner: tailscaleExecRunner{},
	}
}

func (c TailscaleCollector) Collect(ctx context.Context) (model.TailscaleState, error) {
	statusPayload, err := c.Runner.Status(ctx)
	if err != nil {
		failure := classifyTailscaleCollectionFailure(err)
		return model.TailscaleState{
			Status:            model.TailscaleStatus{Detail: err.Error()},
			CollectionError:   failure.Detail,
			CollectionFailure: failure,
		}, err
	}

	var status tailscaleStatusResponse
	if err := json.Unmarshal(statusPayload, &status); err != nil {
		failure := classifyTailscaleCollectionFailure(err)
		return model.TailscaleState{
			Status:            model.TailscaleStatus{Detail: fmt.Sprintf("decode status: %v", err)},
			CollectionError:   failure.Detail,
			CollectionFailure: failure,
		}, err
	}

	var state model.TailscaleState

	prefsLoaded := false
	prefsPayload, err := c.Runner.Prefs(ctx)
	var prefs tailscalePrefsResponse
	if err != nil {
		state.Roles.Detail = err.Error()
	} else if err := json.Unmarshal(prefsPayload, &prefs); err != nil {
		state.Roles.Detail = fmt.Sprintf("decode prefs: %v", err)
	} else {
		prefsLoaded = true
	}

	state.Status = model.TailscaleStatus{
		Running:        status.BackendState == "Running" && (!prefsLoaded || prefs.WantRunning),
		BackendState:   status.BackendState,
		Authenticated:  status.HaveNodeKey && status.AuthURL == "" && (!prefsLoaded || !prefs.LoggedOut),
		Version:        status.Version,
		HostName:       status.Self.HostName,
		DNSName:        status.Self.DNSName,
		Tailnet:        status.CurrentTailnet.Name,
		MagicDNSSuffix: firstNonEmpty(status.CurrentTailnet.MagicDNSSuffix, status.MagicDNSSuffix),
		Detail:         strings.Join(status.Health, "; "),
	}
	state.Addresses = tailscaleAddressesFrom(status.TailscaleIPs, status.Self.TailscaleIPs)
	state.Status.Connected = state.Status.Running &&
		state.Status.Authenticated &&
		status.Self.Online &&
		(state.Addresses.IPv4 != "" || state.Addresses.IPv6 != "")

	state.Peers = tailscalePeersFrom(status.Peer)
	if prefsLoaded {
		state.Roles.AdvertisedRoutes = model.SortedUnique(prefs.AdvertiseRoutes)
		state.Roles.AdvertisesExitNode = advertisesExitNode(state.Roles.AdvertisedRoutes)
	}

	return state, nil
}

func classifyTailscaleCollectionFailure(err error) model.CollectionFailure {
	switch {
	case isTailscaleCommandUnavailable(err):
		return model.NewCollectionFailure(
			model.CollectionFailureCommandUnavailable,
			"Tailscale command unavailable",
			err,
		)
	case isTailscaleInvalidResponseError(err):
		return model.NewCollectionFailure(
			model.CollectionFailureInvalidResponse,
			"Tailscale status response invalid",
			err,
		)
	case isTailscaleCommandFailed(err):
		return model.NewCollectionFailure(
			model.CollectionFailureCommandFailed,
			"Tailscale status command failed",
			err,
		)
	default:
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"Tailscale collection failed",
			err,
		)
	}
}

func isTailscaleCommandUnavailable(err error) bool {
	_, ok := errors.AsType[*exec.Error](err)
	return ok
}

func isTailscaleCommandFailed(err error) bool {
	_, ok := errors.AsType[*exec.ExitError](err)
	return ok
}

func isTailscaleInvalidResponseError(err error) bool {
	if _, ok := errors.AsType[*json.SyntaxError](err); ok {
		return true
	}
	_, ok := errors.AsType[*json.UnmarshalTypeError](err)
	return ok
}

type tailscaleExecRunner struct{}

func (tailscaleExecRunner) Status(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
}

func (tailscaleExecRunner) Prefs(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "tailscale", "debug", "prefs").Output()
}

type tailscaleStatusResponse struct {
	Version        string                           `json:"Version"`
	BackendState   string                           `json:"BackendState"`
	HaveNodeKey    bool                             `json:"HaveNodeKey"`
	AuthURL        string                           `json:"AuthURL"`
	TailscaleIPs   []string                         `json:"TailscaleIPs"`
	Health         []string                         `json:"Health"`
	MagicDNSSuffix string                           `json:"MagicDNSSuffix"`
	CurrentTailnet tailscaleTailnetResponse         `json:"CurrentTailnet"`
	Self           tailscalePeerResponse            `json:"Self"`
	Peer           map[string]tailscalePeerResponse `json:"Peer"`
}

type tailscaleTailnetResponse struct {
	Name            string `json:"Name"`
	MagicDNSSuffix  string `json:"MagicDNSSuffix"`
	MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
}

type tailscalePeerResponse struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	CurAddr      string   `json:"CurAddr"`
	Relay        string   `json:"Relay"`
	Online       bool     `json:"Online"`
	Active       bool     `json:"Active"`
	InMagicSock  bool     `json:"InMagicSock"`
	InEngine     bool     `json:"InEngine"`
}

type tailscalePrefsResponse struct {
	WantRunning     bool     `json:"WantRunning"`
	LoggedOut       bool     `json:"LoggedOut"`
	AdvertiseRoutes []string `json:"AdvertiseRoutes"`
}

func tailscaleAddressesFrom(primary []string, fallback []string) model.TailscaleAddresses {
	values := primary
	if len(values) == 0 {
		values = fallback
	}

	out := model.TailscaleAddresses{}
	for _, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if out.IPv4 == "" {
				out.IPv4 = ip4.String()
			}
			continue
		}
		if ip16 := ip.To16(); ip16 != nil && out.IPv6 == "" {
			out.IPv6 = ip16.String()
		}
	}
	return out
}

func tailscalePeersFrom(peers map[string]tailscalePeerResponse) model.TailscalePeers {
	out := model.TailscalePeers{
		Total: uint64(len(peers)),
	}
	for _, peer := range peers {
		if !peer.Online {
			continue
		}
		out.Online++
		if peer.Active && peer.CurAddr != "" {
			out.Direct++
			continue
		}
		if peer.Relay != "" {
			out.Relay++
			continue
		}
		if peer.InEngine || peer.InMagicSock {
			out.Direct++
		}
	}
	return out
}

func advertisesExitNode(routes []string) bool {
	var hasV4 bool
	var hasV6 bool
	for _, route := range routes {
		switch strings.TrimSpace(route) {
		case "0.0.0.0/0":
			hasV4 = true
		case "::/0":
			hasV6 = true
		}
	}
	return hasV4 && hasV6
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
