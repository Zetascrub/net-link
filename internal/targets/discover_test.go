package targets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromCIDR(t *testing.T) {
	targets, err := FromCIDR("192.168.1.0/30", []int{80, 443}, 8, false)
	if err != nil {
		t.Fatalf("FromCIDR returned error: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %d targets, want 4", len(targets))
	}
	if targets[0].Host != "192.168.1.1" || targets[0].Port != 80 {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[3].Host != "192.168.1.2" || targets[3].Port != 443 {
		t.Fatalf("unexpected last target: %+v", targets[3])
	}
}

func TestFromCIDRMaxHosts(t *testing.T) {
	if _, err := FromCIDR("192.168.1.0/24", []int{80}, 16, false); err == nil {
		t.Fatal("expected max-hosts error")
	}
}

func TestFromCIDRBlocksPublicByDefault(t *testing.T) {
	if _, err := FromCIDR("8.8.8.0/24", []int{53}, 256, false); err == nil {
		t.Fatal("expected public CIDR to be blocked")
	}
}

func TestFromCIDRAllowsSharedCrostiniRange(t *testing.T) {
	targets, err := FromCIDR("100.115.92.0/30", []int{443}, 8, false)
	if err != nil {
		t.Fatalf("shared range rejected: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
}

func TestPrivateIPv4RoutesFiltersDefaultPublicAndVirtualRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	data := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n" +
		"eth0 0002A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\n" +
		"eth0 00080808 00000000 0001 0 0 100 00FFFFFF 0 0 0\n" +
		"docker0 000011AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	routes, err := privateIPv4Routes(path, AutoNetworkOptions{ExcludeVirtual: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0] != "192.168.2.0/24" {
		t.Fatalf("routes = %v, want [192.168.2.0/24]", routes)
	}
}

func TestInterfaceSelection(t *testing.T) {
	if interfaceSelected("docker0", AutoNetworkOptions{ExcludeVirtual: true}) {
		t.Fatal("docker0 should be excluded by default")
	}
	if !interfaceSelected("docker0", AutoNetworkOptions{ExcludeVirtual: true, IncludeInterfaces: []string{"docker0"}}) {
		t.Fatal("explicit interface inclusion should override virtual defaults")
	}
	if interfaceSelected("eth0", AutoNetworkOptions{ExcludeInterfaces: []string{"eth0"}}) {
		t.Fatal("explicitly excluded interface was selected")
	}
}

func TestFromNetworksDeduplicatesAndLimitsTotalHosts(t *testing.T) {
	targets, err := FromNetworks([]string{"192.168.1.0/30", "192.168.1.1/32"}, []int{443}, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2 unique targets", len(targets))
	}
	if _, err := FromNetworks([]string{"192.168.1.0/30"}, []int{443}, 8, 1); err == nil {
		t.Fatal("expected max-total-hosts error")
	}
}
