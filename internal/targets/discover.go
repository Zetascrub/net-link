package targets

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/policy"
)

func FromCIDR(cidr string, ports []int, maxHosts int, allowPublic bool) ([]model.Target, error) {
	if maxHosts <= 0 {
		return nil, fmt.Errorf("max hosts must be greater than zero")
	}
	if err := policy.CheckTargetAllowed(cidr, allowPublic); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		ports = commonPorts
	}

	ips, err := expandIPv4CIDR(cidr, maxHosts)
	if err != nil {
		return nil, err
	}
	return fromHosts(ips, ports, model.SourceDiscovery), nil
}

func FromCIDRList(scope string, ports []int, maxHosts int, allowPublic bool) ([]model.Target, error) {
	var out []model.Target
	for _, part := range strings.Split(scope, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		targets, err := FromCIDR(part, ports, maxHosts, allowPublic)
		if err != nil {
			return nil, err
		}
		out = append(out, targets...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no discovery scopes provided")
	}
	return out, nil
}

func FromLocalNetworks(ports []int, maxHosts int) ([]model.Target, []string, error) {
	networks, err := LocalPrivateIPv4Networks()
	if err != nil {
		return nil, nil, err
	}
	if len(networks) == 0 {
		return nil, nil, fmt.Errorf("no private IPv4 networks found")
	}

	var out []model.Target
	for _, network := range networks {
		targets, err := FromCIDR(network, ports, maxHosts, false)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, targets...)
	}
	return out, networks, nil
}

func LocalPrivateIPv4Networks() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var networks []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !ip.IsPrivate() {
				continue
			}
			network := &net.IPNet{IP: ip.Mask(ipNet.Mask), Mask: ipNet.Mask}
			key := network.String()
			if !seen[key] {
				seen[key] = true
				networks = append(networks, key)
			}
		}
	}
	return networks, nil
}

func expandIPv4CIDR(cidr string, maxHosts int) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR discovery is supported right now: %s", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 CIDR discovery is supported right now: %s", cidr)
	}

	total := uint64(1) << uint64(bits-ones)
	if total > uint64(maxHosts) {
		return nil, fmt.Errorf("scope %s contains %d addresses; increase --max-hosts above %d to scan it", cidr, total, maxHosts)
	}

	start := binary.BigEndian.Uint32(ip.Mask(ipNet.Mask))
	var first uint32
	var last uint32
	if total <= 2 {
		first = start
		last = start + uint32(total) - 1
	} else {
		first = start + 1
		last = start + uint32(total) - 2
	}

	ips := make([]string, 0, int(total))
	for current := first; current <= last; current++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], current)
		ips = append(ips, net.IPv4(b[0], b[1], b[2], b[3]).String())
	}
	return ips, nil
}
