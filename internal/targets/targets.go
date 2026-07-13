package targets

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Zetascrub/net-link/internal/ids"
	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/policy"
)

var commonPorts = []int{22, 53, 80, 135, 139, 389, 443, 445, 3389, 8080, 8443}

func FromHost(host string, ports []int, allowPublic bool) ([]model.Target, error) {
	if host == "" {
		return nil, fmt.Errorf("target host is required")
	}
	hosts, err := policy.ResolveHostAllowed(context.Background(), host, allowPublic)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		ports = commonPorts
	}

	return fromHosts(hosts, ports, model.SourceManual), nil
}

func fromHosts(hosts []string, ports []int, sourceType string) []model.Target {
	out := make([]model.Target, 0, len(ports))
	for _, host := range hosts {
		for _, port := range ports {
			out = append(out, model.Target{
				ID:       ids.New("target"),
				Host:     host,
				Port:     port,
				Protocol: model.ProtocolTCP,
				Service:  ServiceForPort(port),
				Source: model.TargetSource{
					Type: sourceType,
				},
			})
		}
	}
	return out
}

func ParsePorts(input string) ([]int, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}

	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for port := start; port <= end; port++ {
				if !seen[port] {
					seen[port] = true
					ports = append(ports, port)
				}
			}
			continue
		}

		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func parsePort(input string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", input)
	}
	return port, nil
}

func ServiceForPort(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 53:
		return "dns"
	case 80, 8080:
		return "http"
	case 135:
		return "msrpc"
	case 139, 445:
		return "smb"
	case 389:
		return "ldap"
	case 443, 8443:
		return "https"
	case 3389:
		return "rdp"
	default:
		return ""
	}
}
