package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStartProxyAuthForwarderNoCredentials(t *testing.T) {
	got, stop, err := startProxyAuthForwarder("http://proxy.local:3128", nil)
	if err != nil {
		t.Fatalf("startProxyAuthForwarder: %v", err)
	}
	defer stop()
	if got != "http://proxy.local:3128" {
		t.Fatalf("got %q, want the url returned unchanged", got)
	}
}

// TestProxyAuthForwarderInjectsHTTP verifies a plain-HTTP proxied request is
// forwarded with Proxy-Authorization added.
func TestProxyAuthForwarderInjectsHTTP(t *testing.T) {
	const user, pass = "runeward", "s3cret"
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		io.WriteString(w, "OK BODY")
	}))
	defer upstream.Close()

	raw := "http://" + user + ":" + pass + "@" + strings.TrimPrefix(upstream.URL, "http://")
	local, stop, err := startProxyAuthForwarder(raw, nil)
	if err != nil {
		t.Fatalf("startProxyAuthForwarder: %v", err)
	}
	defer stop()

	conn, err := net.Dial("tcp", strings.TrimPrefix(local, "http://"))
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "OK BODY" {
		t.Fatalf("status=%d body=%q, want 200 / OK BODY (auth was not injected)", resp.StatusCode, body)
	}
}

// TestProxyAuthForwarderInjectsConnect verifies the CONNECT (HTTPS tunnel) path
// authenticates to the upstream and relays bytes buffered past the handshake.
func TestProxyAuthForwarderInjectsConnect(t *testing.T) {
	const user, pass = "runeward", "s3cret"
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if req.Header.Get("Proxy-Authorization") != want {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\n\r\n")
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nTUNNEL-OK")
			}()
		}
	}()

	raw := "http://" + user + ":" + pass + "@" + ln.Addr().String()
	local, stop, err := startProxyAuthForwarder(raw, nil)
	if err != nil {
		t.Fatalf("startProxyAuthForwarder: %v", err)
	}
	defer stop()

	conn, err := net.Dial("tcp", strings.TrimPrefix(local, "http://"))
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect status=%d, want 200 (auth was not injected)", resp.StatusCode)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "TUNNEL-OK" {
		t.Fatalf("tunneled bytes=%q, want %q", rest, "TUNNEL-OK")
	}
}
