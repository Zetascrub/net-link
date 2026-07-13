package policy

import (
	"context"
	"testing"
)

func TestResolveHostAllowedResolvesLocalhost(t *testing.T) {
	addresses, err := ResolveHostAllowed(context.Background(), "localhost", false)
	if err != nil {
		t.Fatalf("ResolveHostAllowed: %v", err)
	}
	if len(addresses) == 0 {
		t.Fatal("localhost resolved to no addresses")
	}
}

func TestResolveHostAllowedRejectsPublicAndSpecialAddresses(t *testing.T) {
	for _, host := range []string{"8.8.8.8", "0.0.0.0", "224.0.0.1", "::"} {
		t.Run(host, func(t *testing.T) {
			if _, err := ResolveHostAllowed(context.Background(), host, false); err == nil {
				t.Fatalf("expected %s to be rejected", host)
			}
		})
	}
}

func TestResolveHostAllowedNeverAllowsMulticast(t *testing.T) {
	if _, err := ResolveHostAllowed(context.Background(), "224.0.0.1", true); err == nil {
		t.Fatal("multicast target was allowed with allowPublic")
	}
}

func TestResolveHostAllowedAllowsSharedCrostiniAddressSpace(t *testing.T) {
	addresses, err := ResolveHostAllowed(context.Background(), "100.115.92.2", false)
	if err != nil {
		t.Fatalf("Crostini shared address rejected: %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "100.115.92.2" {
		t.Fatalf("resolved addresses = %v", addresses)
	}
}
