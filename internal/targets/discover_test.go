package targets

import "testing"

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
