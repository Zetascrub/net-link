package targets

import "testing"

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("22,80,443-445,80")
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}

	want := []int{22, 80, 443, 444, 445}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestFromHostBlocksPublicByDefault(t *testing.T) {
	if _, err := FromHost("8.8.8.8", []int{53}, false); err == nil {
		t.Fatal("expected public target to be blocked")
	}
}

func TestFromHostAllowsPrivateTarget(t *testing.T) {
	targets, err := FromHost("192.168.1.10", []int{443}, false)
	if err != nil {
		t.Fatalf("FromHost returned error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Service != "https" {
		t.Fatalf("got service %q, want https", targets[0].Service)
	}
}
