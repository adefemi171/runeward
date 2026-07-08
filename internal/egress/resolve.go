package egress

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const resolveTimeout = 5 * time.Second

var lookupIPAddrs = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func hostWithDefaultPort(authority, defaultPort string) (host, port string, err error) {
	if authority == "" {
		return "", "", fmt.Errorf("empty authority")
	}
	if h, p, err := net.SplitHostPort(authority); err == nil {
		return strings.Trim(strings.TrimSpace(h), "[]"), p, nil
	}
	h := strings.Trim(strings.TrimSpace(authority), "[]")
	return h, defaultPort, nil
}

func pickPinnedIP(host string, dstHint net.IP) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := lookupIPAddrs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IPs resolved for %q", host)
	}
	if dstHint != nil {
		for _, a := range addrs {
			if a.IP.Equal(dstHint) {
				return a.IP, nil
			}
		}
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP, nil
		}
	}
	return addrs[0].IP, nil
}

func pinnedAddrForHost(host, port string, dstHint net.IP) (string, error) {
	ip, err := pickPinnedIP(host, dstHint)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}
