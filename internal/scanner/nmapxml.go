package scanner

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/Zetascrub/net-link/internal/ids"
	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/policy"
	"github.com/Zetascrub/net-link/internal/targets"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name string `xml:"name,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

func ParseNmapXMLFile(path string, allowPublic bool) ([]model.Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseNmapXML(data, path, allowPublic)
}

func ParseNmapXML(data []byte, sourceFile string, allowPublic bool) ([]model.Target, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", err)
	}

	sourceType := model.SourceNmapXML
	if sourceFile == "nmap:-" {
		sourceType = model.SourceNmapExecution
	}

	var out []model.Target
	for _, host := range run.Hosts {
		addr := firstAddress(host)
		if addr == "" {
			continue
		}
		if err := policy.CheckHostAllowed(addr, allowPublic); err != nil {
			return nil, err
		}
		for _, port := range host.Ports {
			if port.State.State != "open" || port.Protocol != model.ProtocolTCP {
				continue
			}
			service := port.Service.Name
			if service == "" {
				service = targets.ServiceForPort(port.PortID)
			}
			out = append(out, model.Target{
				ID:       ids.New("target"),
				Host:     addr,
				Port:     port.PortID,
				Protocol: port.Protocol,
				Service:  service,
				Source: model.TargetSource{
					Type: sourceType,
					File: sourceFile,
				},
			})
		}
	}
	return out, nil
}

func firstAddress(host nmapHost) string {
	for _, addr := range host.Addresses {
		if addr.Type == "ipv4" || addr.Type == "ipv6" {
			return addr.Addr
		}
	}
	if len(host.Addresses) > 0 {
		return host.Addresses[0].Addr
	}
	return ""
}
