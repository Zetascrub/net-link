package policy

import (
	"context"
	"fmt"
	"net"
)

var sharedAddressSpace = mustCIDR("100.64.0.0/10")

func CheckHostAllowed(host string, allowPublic bool) error {
	ip := net.ParseIP(host)
	if ip == nil {
		_, err := ResolveHostAllowed(context.Background(), host, allowPublic)
		return err
	}
	if isForbidden(ip) {
		return fmt.Errorf("target %s is an unspecified or multicast address", host)
	}
	if allowPublic || isAllowedInternal(ip) {
		return nil
	}
	return fmt.Errorf("target %s is public; pass --allow-public to permit public targets", host)
}

func CheckTargetAllowed(target string, allowPublic bool) error {
	if ip, network, err := net.ParseCIDR(target); err == nil {
		if isForbidden(ip) {
			return fmt.Errorf("target %s is an unspecified or multicast range", target)
		}
		if allowPublic || cidrIsAllowedInternal(network) {
			return nil
		}
		return fmt.Errorf("target %s is public; pass --allow-public to permit public targets", target)
	}
	return CheckHostAllowed(target, allowPublic)
}

func cidrIsAllowedInternal(network *net.IPNet) bool {
	first := network.IP.Mask(network.Mask)
	last := append(net.IP(nil), first...)
	for i := range last {
		last[i] |= ^network.Mask[i]
	}
	return isAllowedInternal(first) && isAllowedInternal(last)
}

func ResolveHostAllowed(ctx context.Context, host string, allowPublic bool) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isForbidden(ip) {
			return nil, fmt.Errorf("target %s is an unspecified or multicast address", host)
		}
		if !allowPublic && !isAllowedInternal(ip) {
			return nil, fmt.Errorf("target %s is public or special-use; pass --allow-public to permit it", host)
		}
		return []string{ip.String()}, nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve target %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("target %s resolved to no addresses", host)
	}
	seen := map[string]bool{}
	resolved := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if isForbidden(address.IP) {
			return nil, fmt.Errorf("target %s resolves to unspecified or multicast address %s", host, address.IP)
		}
		if !allowPublic && !isAllowedInternal(address.IP) {
			return nil, fmt.Errorf("target %s resolves to public or special-use address %s; pass --allow-public to permit it", host, address.IP)
		}
		value := address.IP.String()
		if !seen[value] {
			seen[value] = true
			resolved = append(resolved, value)
		}
	}
	return resolved, nil
}

func IsAllowedInternal(ip net.IP) bool {
	return isAllowedInternal(ip)
}

func isAllowedInternal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || sharedAddressSpace.Contains(ip)
}

func isForbidden(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsMulticast()
}

func mustCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}
