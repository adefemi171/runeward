package egress

import (
	"context"
	"net"
	"testing"
)

func TestPinnedAddrForHostPrefersOriginalDst(t *testing.T) {
	prevLookup := lookupIPAddrs
	lookupIPAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("203.0.113.4")},
			{IP: net.ParseIP("198.51.100.9")},
		}, nil
	}
	defer func() { lookupIPAddrs = prevLookup }()

	got, err := pinnedAddrForHost("api.example.com", "443", net.ParseIP("198.51.100.9"))
	if err != nil {
		t.Fatalf("pinnedAddrForHost failed: %v", err)
	}
	want := "198.51.100.9:443"
	if got != want {
		t.Fatalf("pinnedAddrForHost = %q, want %q", got, want)
	}
}

func TestHostWithDefaultPort(t *testing.T) {
	host, port, err := hostWithDefaultPort("example.com", "80")
	if err != nil {
		t.Fatalf("hostWithDefaultPort: %v", err)
	}
	if host != "example.com" || port != "80" {
		t.Fatalf("got (%q,%q), want (%q,%q)", host, port, "example.com", "80")
	}
}
