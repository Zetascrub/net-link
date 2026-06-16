package policy

import (
	"fmt"
	"net"
)

func CheckHostAllowed(host string, allowPublic bool) error {
	if allowPublic {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Hostnames are not resolved here; the resolved IP may be private or
		// public and is unknown until dial time. Operators are responsible for
		// ensuring hostname targets are in scope.
		return nil
	}
	if isInternal(ip) {
		return nil
	}
	return fmt.Errorf("target %s is public; pass --allow-public to permit public targets", host)
}

func CheckTargetAllowed(target string, allowPublic bool) error {
	if allowPublic {
		return nil
	}

	if ip, _, err := net.ParseCIDR(target); err == nil {
		if isInternal(ip) {
			return nil
		}
		return fmt.Errorf("target %s is public; pass --allow-public to permit public targets", target)
	}
	return CheckHostAllowed(target, allowPublic)
}

func isInternal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
