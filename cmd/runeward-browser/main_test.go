package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/Runewardd/runeward/internal/browser"
)

func TestBrowserNoSandboxEnabled(t *testing.T) {
	// Default (unset) is ON: containers usually lack the user namespaces
	// Chromium's own sandbox needs, matching the one-shot render path.
	t.Setenv(envBrowserNoSandbox, "")
	if !browserNoSandboxEnabled() {
		t.Fatal("expected no-sandbox to default to enabled")
	}
	t.Setenv(envBrowserNoSandbox, "1")
	if !browserNoSandboxEnabled() {
		t.Fatal("expected no-sandbox to be enabled")
	}
	// Explicit opt-out keeps Chromium's sandbox (userns/gVisor/Kata hosts).
	for _, off := range []string{"0", "false", "no", "off"} {
		t.Setenv(envBrowserNoSandbox, off)
		if browserNoSandboxEnabled() {
			t.Fatalf("expected no-sandbox to be disabled for %q", off)
		}
	}
}

func TestListenControlTCP(t *testing.T) {
	ln, network, err := listenControl("tcp://127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenControl tcp: %v", err)
	}
	defer ln.Close()
	if network != "tcp" {
		t.Fatalf("network = %q, want %q", network, "tcp")
	}
}

func TestHandleConnRejectsInvalidToken(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	d := &driver{token: "shared-secret"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleConn(serverConn)
	}()

	if err := json.NewEncoder(clientConn).Encode(browser.Command{Action: "ping", Token: "wrong"}); err != nil {
		t.Fatalf("encode command: %v", err)
	}
	var res browser.Result
	if err := json.NewDecoder(clientConn).Decode(&res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	<-done
	if res.OK {
		t.Fatal("expected unauthorized result")
	}
	if !strings.Contains(res.Error, "unauthorized") {
		t.Fatalf("error = %q, want unauthorized", res.Error)
	}
}
