package scanner

import "testing"

func TestParseNmapXML(t *testing.T) {
	input := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	targets, err := ParseNmapXML(input, "scan.xml", false)
	if err != nil {
		t.Fatalf("ParseNmapXML returned error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Host != "10.0.0.5" || targets[0].Port != 22 || targets[0].Service != "ssh" {
		t.Fatalf("unexpected target: %+v", targets[0])
	}
}
