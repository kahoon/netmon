package collector

import (
	"context"
	"errors"
	"net"

	"github.com/kahoon/netmon/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type InterfaceCollector struct {
	// Name is the network interface to collect state from (e.g. "eno1").
	Name string
}

func (c InterfaceCollector) Collect(_ context.Context) (model.InterfaceState, error) {
	link, err := netlink.LinkByName(c.Name)
	if err != nil {
		failure := classifyInterfaceCollectionFailure(err)
		return model.InterfaceState{
			IfName:            c.Name,
			CollectionError:   failure.Detail,
			CollectionFailure: failure,
		}, err
	}

	attrs := link.Attrs()
	state := model.InterfaceState{
		LinkIndex: attrs.Index,
		IfName:    attrs.Name,
		LinkUp:    attrs.Flags&net.FlagUp != 0,
		OperState: attrs.OperState.String(),
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		state.CollectionFailure = classifyInterfaceCollectionFailure(err)
		state.CollectionError = state.CollectionFailure.Detail
		return state, err
	}

	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			continue
		}

		switch classifyIP(ip) {
		case "gua":
			state.GUA = append(state.GUA, model.NormalizeIP(ip))
			if isUsableGUA(addr) {
				state.UsableGUA = append(state.UsableGUA, model.NormalizeIP(ip))
			}
		case "ula":
			state.ULA = append(state.ULA, model.NormalizeIP(ip))
		}
	}

	state.ULA = model.SortedUnique(state.ULA)
	state.GUA = model.SortedUnique(state.GUA)
	state.UsableGUA = model.SortedUnique(state.UsableGUA)

	return state, nil
}

func classifyInterfaceCollectionFailure(err error) model.CollectionFailure {
	_, isNotFound := errors.AsType[netlink.LinkNotFoundError](err)
	switch {
	case isNotFound:
		return model.NewCollectionFailure(
			model.CollectionFailureUnavailable,
			"monitor interface not found",
			err,
		)
	case errors.Is(err, unix.EPERM):
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"interface collection permission denied",
			err,
		)
	default:
		return model.NewCollectionFailure(
			model.CollectionFailureGeneric,
			"interface collection failed",
			err,
		)
	}
}

func classifyIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return "ipv4"
	}
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	if ip.IsLinkLocalUnicast() {
		return "llv6"
	}
	if isULA(ip) {
		return "ula"
	}
	if isGUA(ip) {
		return "gua"
	}
	return ""
}

func isULA(ip net.IP) bool {
	ip = ip.To16()
	return ip != nil && (ip[0]&0xfe) == 0xfc
}

func isGUA(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	if isULA(ip) {
		return false
	}
	return ip.IsGlobalUnicast()
}

func isUsableGUA(addr netlink.Addr) bool {
	if addr.Flags&unix.IFA_F_TENTATIVE != 0 {
		return false
	}
	if addr.Flags&unix.IFA_F_DEPRECATED != 0 {
		return false
	}
	return true
}
