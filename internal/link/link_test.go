package link

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalPeerUsesPersistentEd25519Identity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	first, err := LocalPeer("test", DefaultDiscoveryPort, DefaultLinkPort)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LocalPeer("test", DefaultDiscoveryPort, DefaultLinkPort)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.PublicKey == "" || first.ID != second.ID || first.PublicKey != second.PublicKey {
		t.Fatalf("identity was not persistent: first=%+v second=%+v", first, second)
	}
	info, err := os.Stat(filepath.Join(dir, "net-link", "identity-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("identity permissions = %04o, want 0600", got)
	}
}

func TestReadWireRejectsOversizedMessage(t *testing.T) {
	var message wireMessage
	err := readWire(strings.NewReader(strings.Repeat("x", maxWireMessageBytes+1)), &message)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readWire error = %v, want size-limit error", err)
	}
}

func TestHandleLinkRejectsRemoteChecksByDefault(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleLink(server, Peer{ID: "peer_test", Name: "test-peer"}, servicePolicy{}, io.Discard)
	}()

	err := writeWire(client, wireMessage{
		Type:     serviceMessageType,
		Protocol: protocolVersion,
		Targets: []ServiceTarget{
			{Host: "192.0.2.1", Port: 443},
		},
	})
	if err != nil {
		t.Fatalf("write service request: %v", err)
	}

	var response wireMessage
	if err := readWire(client, &response); err != nil {
		t.Fatalf("read service response: %v", err)
	}
	if response.Type != serviceResultType {
		t.Fatalf("response type = %q, want %q", response.Type, serviceResultType)
	}
	if !strings.Contains(response.Error, "disabled") {
		t.Fatalf("response error = %q, want disabled error", response.Error)
	}
	if len(response.Results) != 0 {
		t.Fatalf("got %d results; disabled handler must not run checks", len(response.Results))
	}
	<-done
}

func TestListenRejectsInvalidBindAddress(t *testing.T) {
	err := Listen(context.Background(), ListenOptions{BindAddress: "not-an-ip"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "bind address") {
		t.Fatalf("Listen error = %v, want bind-address validation error", err)
	}
}

func TestServicePolicyRequiresExplicitScopeAndPorts(t *testing.T) {
	if _, err := newServicePolicy(true, nil, []int{443}); err == nil {
		t.Fatal("expected missing scope to be rejected")
	}
	if _, err := newServicePolicy(true, []string{"192.168.1.0/24"}, nil); err == nil {
		t.Fatal("expected missing ports to be rejected")
	}
	if _, err := newServicePolicy(true, []string{"10.0.0.0/7"}, []int{443}); err == nil {
		t.Fatal("expected partially public CIDR to be rejected")
	}
}

func TestServicePolicyAuthorizesOnlyConfiguredTargets(t *testing.T) {
	policy, err := newServicePolicy(true, []string{"192.168.1.0/24"}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.authorize([]ServiceTarget{{Host: "192.168.1.20", Port: 443}}); err != nil {
		t.Fatalf("configured target rejected: %v", err)
	}
	for _, target := range []ServiceTarget{
		{Host: "192.168.2.20", Port: 443},
		{Host: "192.168.1.20", Port: 80},
		{Host: "8.8.8.8", Port: 443},
		{Host: "example.test", Port: 443},
	} {
		if err := policy.authorize([]ServiceTarget{target}); err == nil {
			t.Fatalf("unauthorized target accepted: %+v", target)
		}
	}
}
