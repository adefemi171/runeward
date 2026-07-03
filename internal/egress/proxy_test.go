package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// startTargetListener starts a raw TCP listener that reads one line and
// writes back a fixed reply.
func startTargetListener(t *testing.T, reply string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		_, _ = br.ReadString('\n')
		_, _ = io.WriteString(conn, reply)
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func newProxyServer(t *testing.T, p *Proxy) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectAllowed(t *testing.T) {
	targetAddr, stop := startTargetListener(t, "pong\n")
	defer stop()

	host, _, _ := net.SplitHostPort(targetAddr)
	p := &Proxy{Policy: Policy{
		Default: "deny",
		Rules:   []Rule{{Verdict: "allow", Hostname: host}},
	}}
	srv := newProxyServer(t, p)
	proxyAddr := strings.TrimPrefix(srv.URL, "http://")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("expected 200 Connection Established, got %q", status)
	}
	// Consume the rest of the response header block.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// The connection is now a raw tunnel; verify bytes flow.
	fmt.Fprintf(conn, "ping\n")
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != "pong" {
		t.Fatalf("tunnel echo = %q, want pong", got)
	}
}

func TestConnectDenied(t *testing.T) {
	p := &Proxy{Policy: Policy{Default: "deny"}}
	srv := newProxyServer(t, p)
	proxyAddr := strings.TrimPrefix(srv.URL, "http://")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "403") {
		t.Fatalf("expected 403 Forbidden, got %q", status)
	}
}

func TestHTTPDenied(t *testing.T) {
	p := &Proxy{Policy: Policy{Default: "deny"}}
	srv := newProxyServer(t, p)

	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("http://denied.example.com/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHTTPAllowedForwards(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello-from-origin")
	}))
	defer origin.Close()

	originHost := strings.TrimPrefix(origin.URL, "http://")
	host, _, _ := net.SplitHostPort(originHost)

	p := &Proxy{Policy: Policy{
		Default: "deny",
		Rules:   []Rule{{Verdict: "allow", Hostname: host}},
	}}
	srv := newProxyServer(t, p)

	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello-from-origin" {
		t.Fatalf("body = %q, want hello-from-origin", body)
	}
}
