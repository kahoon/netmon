package rpc

import "net"

func probeHasFamily(bindings []string, family int) bool {
	for _, binding := range bindings {
		host, _, err := net.SplitHostPort(binding)
		if err != nil {
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}

		switch family {
		case 4:
			if ip.To4() != nil {
				return true
			}
		case 6:
			if ip.To4() == nil && ip.To16() != nil {
				return true
			}
		}
	}

	return false
}
