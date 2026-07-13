package targets

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/policy"
)

type AutoNetworkOptions struct {
	IncludeInterfaces []string
	ExcludeInterfaces []string
	ExcludeVirtual    bool
	IncludeRoutes     bool
}

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

func FromNetworks(networks []string, ports []int, maxHosts, maxTotalHosts int) ([]model.Target, error) {
	if maxTotalHosts <= 0 {
		return nil, fmt.Errorf("max total hosts must be greater than zero")
	}
	seenHosts := map[string]bool{}
	seenTargets := map[string]bool{}
	var out []model.Target
	for _, network := range networks {
		generated, err := FromCIDR(network, ports, maxHosts, false)
		if err != nil {
			return nil, err
		}
		for _, target := range generated {
			if !seenHosts[target.Host] {
				if len(seenHosts) >= maxTotalHosts {
					return nil, fmt.Errorf("automatic scope exceeds --max-total-hosts=%d", maxTotalHosts)
				}
				seenHosts[target.Host] = true
			}
			key := fmt.Sprintf("%s:%d/%s", target.Host, target.Port, target.Protocol)
			if !seenTargets[key] {
				seenTargets[key] = true
				out = append(out, target)
			}
		}
	}
	return out, nil
}

func LocalPrivateIPv4Networks() ([]string, error) {
	return AutoPrivateIPv4Networks(AutoNetworkOptions{})
}

func AutoPrivateIPv4Networks(opts AutoNetworkOptions) ([]string, error) {
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
		if !interfaceSelected(iface.Name, opts) {
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
			if ip == nil || !policy.IsAllowedInternal(ip) {
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
	if opts.IncludeRoutes {
		routes, err := privateIPv4Routes("/proc/net/route", opts)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, route := range routes {
			if !seen[route] {
				seen[route] = true
				networks = append(networks, route)
			}
		}
	}
	return networks, nil
}

func interfaceSelected(name string, opts AutoNetworkOptions) bool {
	if len(opts.IncludeInterfaces) > 0 && !containsString(opts.IncludeInterfaces, name) {
		return false
	}
	if containsString(opts.ExcludeInterfaces, name) {
		return false
	}
	if opts.ExcludeVirtual && len(opts.IncludeInterfaces) == 0 {
		lower := strings.ToLower(name)
		for _, prefix := range []string{"docker", "br-", "veth", "cni", "flannel", "podman", "virbr", "tun", "tap", "wg", "zt"} {
			if strings.HasPrefix(lower, prefix) {
				return false
			}
		}
	}
	return true
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func privateIPv4Routes(path string, opts AutoNetworkOptions) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := map[string]bool{}
	var routes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[0] == "Iface" || !interfaceSelected(fields[0], opts) {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&1 == 0 || fields[1] == "00000000" {
			continue
		}
		destination, err1 := routeHexIPv4(fields[1])
		maskIP, err2 := routeHexIPv4(fields[7])
		if err1 != nil || err2 != nil {
			continue
		}
		mask := net.IPMask(maskIP.To4())
		network := &net.IPNet{IP: destination.Mask(mask), Mask: mask}
		if !policy.IsAllowedInternal(destination) {
			continue
		}
		value := network.String()
		if !seen[value] {
			seen[value] = true
			routes = append(routes, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}

func routeHexIPv4(value string) (net.IP, error) {
	n, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return nil, err
	}
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24)), nil
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
