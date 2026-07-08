//go:build linux

package egress

import (
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// soOriginalDst is the SOL_IP getsockopt that returns the pre-DNAT
// destination of an iptables-REDIRECTed connection (linux/netfilter_ipv4.h).
const soOriginalDst = 80

// peekLimit bounds how many leading bytes are read to sniff the hostname.
const peekLimit = 4096

// TransparentProxy enforces a [Policy] on connections redirected to it by
// iptables. Unlike [Proxy] it needs no HTTP(S)_PROXY cooperation: the original
// destination comes from SO_ORIGINAL_DST and the hostname is sniffed from TLS
// SNI or the HTTP Host header. Linux-only.
type TransparentProxy struct {
	Policy Policy
	// SandboxID associates decisions with a sandbox for dashboard egress logs.
	SandboxID string
	// Logger receives allow/deny decisions; nil discards them.
	Logger *log.Logger
}

func (t *TransparentProxy) logf(format string, args ...any) {
	if t.Logger != nil {
		t.Logger.Printf(format, args...)
	}
}

func (t *TransparentProxy) sandboxID() string {
	if id := strings.TrimSpace(t.SandboxID); id != "" {
		return id
	}
	if t.Logger != nil {
		return sandboxIDFromLoggerPrefix(t.Logger.Prefix())
	}
	return ""
}

func (t *TransparentProxy) recordDecision(host, ip string, allow bool, reason string) {
	RecordDecision(t.sandboxID(), host, ip, allow, reason)
}

// Serve handles redirected connections on addr until an accept error occurs.
func (t *TransparentProxy) Serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			continue
		}
		go t.handle(tc)
	}
}

// handle recovers the original destination, sniffs the hostname, applies the
// policy, and splices on allow.
func (t *TransparentProxy) handle(c *net.TCPConn) {
	defer c.Close()

	dst, err := originalDst(c)
	if err != nil {
		t.logf("egress: drop (no original dst: %v)", err)
		return
	}

	peek := make([]byte, peekLimit)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := c.Read(peek)
	_ = c.SetReadDeadline(time.Time{})
	peek = peek[:n]

	host := ""
	if sni, ok := ExtractSNI(peek); ok {
		host = sni
	} else if h, ok := httpHostFromPeek(peek); ok {
		host = h
	}

	allowed := false
	pinnedDst := dst
	switch {
	case host != "":
		// In strict mode, a presented hostname must be explicitly allowlisted.
		allowed = t.Policy.AllowListedHostname(host)
		if allowed {
			dstHost, dstPort, splitErr := net.SplitHostPort(dst)
			if splitErr != nil {
				allowed = false
				t.logf("egress: DENY %s (invalid original dst %q: %v)", host, dst, splitErr)
				t.recordDecision(host, "", false, "invalid original destination")
				break
			}
			pinned, pinErr := pinnedAddrForHost(host, dstPort, net.ParseIP(strings.Trim(dstHost, "[]")))
			if pinErr != nil {
				allowed = false
				t.logf("egress: DENY %s (resolve failed: %v)", host, pinErr)
				t.recordDecision(host, "", false, "hostname resolution failed")
				break
			}
			pinnedDst = pinned
		}
	default:
		// No hostname; fall back to the raw IP against CIDR rules.
		allowed = t.Policy.AllowAddr(dst)
	}

	label := host
	if label == "" {
		label = dst
	}
	pinnedIP, _, _ := net.SplitHostPort(pinnedDst)
	if !allowed {
		t.logf("egress: DENY %s (dst=%s)", label, dst)
		t.recordDecision(label, pinnedIP, false, "blocked by egress policy")
		return
	}
	t.logf("egress: ALLOW %s (dst=%s pinned=%s)", label, dst, pinnedDst)
	t.recordDecision(label, pinnedIP, true, "allowed by egress policy")

	up, err := net.DialTimeout("tcp", pinnedDst, dialTimeout)
	if err != nil {
		t.logf("egress: dial %s failed: %v", pinnedDst, err)
		return
	}
	defer up.Close()

	// Replay the sniffed bytes, then splice bidirectionally.
	if len(peek) > 0 {
		if _, err := up.Write(peek); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
	<-done
}

// originalDst returns the pre-DNAT "ip:port" of a redirected IPv4 connection.
func originalDst(c *net.TCPConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var addr string
	var soErr error
	if err := raw.Control(func(fd uintptr) {
		mreq, e := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if e != nil {
			soErr = e
			return
		}
		// mreq.Multiaddr is a sockaddr_in: [2:4] is the big-endian port,
		// [4:8] the IPv4 address.
		m := mreq.Multiaddr
		port := int(m[2])<<8 | int(m[3])
		ip := net.IPv4(byte(m[4]), byte(m[5]), byte(m[6]), byte(m[7]))
		addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}); err != nil {
		return "", err
	}
	return addr, soErr
}
