package model

import (
	"maps"
	"net"
	"sort"
)

func NormalizeIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	if ip16 := ip.To16(); ip16 != nil {
		return ip16.String()
	}
	return ip.String()
}

func SortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return sortedKeys(set)
}

func CopyCheckSet(in CheckSet) CheckSet {
	out := make(CheckSet, len(in))
	maps.Copy(out, in)
	return out
}

func CopySystemState(in SystemState) SystemState {
	return SystemState{
		Interface: InterfaceState{
			LinkIndex: in.Interface.LinkIndex,
			IfName:    in.Interface.IfName,
			LinkUp:    in.Interface.LinkUp,
			OperState: in.Interface.OperState,
			ULA:       append([]string{}, in.Interface.ULA...),
			GUA:       append([]string{}, in.Interface.GUA...),
			UsableGUA: append([]string{}, in.Interface.UsableGUA...),
		},
		Listeners: ListenerState{
			DNS53TCP:        copySocketProbe(in.Listeners.DNS53TCP),
			DNS53UDP:        copySocketProbe(in.Listeners.DNS53UDP),
			Resolver5335TCP: copySocketProbe(in.Listeners.Resolver5335TCP),
			Resolver5335UDP: copySocketProbe(in.Listeners.Resolver5335UDP),
		},
		Upstream: UpstreamState{
			ExternalDNSV4: in.Upstream.ExternalDNSV4,
			ExternalDNSV6: in.Upstream.ExternalDNSV6,
			PublicIPv4:    in.Upstream.PublicIPv4,
		},
	}
}

func EnsurePort(address, port string) string {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}

	if ip := net.ParseIP(address); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}

	return net.JoinHostPort(address, port)
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func copySocketProbe(in SocketProbe) SocketProbe {
	return SocketProbe{
		Loopback:    append([]string{}, in.Loopback...),
		NonLoopback: append([]string{}, in.NonLoopback...),
	}
}
