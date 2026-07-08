package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// startProxyAuthForwarder works around a Chromium limitation: its
// --proxy-server flag cannot carry credentials, so an upstream proxy that
// requires HTTP Basic auth (like runeward's cooperative egress proxy) rejects
// Chromium with 407 / ERR_NO_SUPPORTED_PROXIES and pages render blank.
//
// When rawProxy embeds user:pass@, we start a tiny loopback proxy that injects
// Proxy-Authorization on the client's behalf and forwards to the upstream. The
// returned URL (http://127.0.0.1:PORT) is credential-free and safe to hand to
// Chromium. When rawProxy has no credentials it is returned unchanged and stop
// is a no-op. The loopback listener is bound to 127.0.0.1 only, so it is no
// more exposed than the upstream proxy credentials already are in the
// container's environment.
func startProxyAuthForwarder(rawProxy string, logger func(string, ...any)) (localURL string, stop func(), err error) {
	noop := func() {}
	u, err := url.Parse(rawProxy)
	if err != nil {
		return "", noop, fmt.Errorf("parse proxy url: %w", err)
	}
	if u.User == nil || u.Host == "" {
		return rawProxy, noop, nil
	}
	pass, _ := u.User.Password()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", noop, fmt.Errorf("listen loopback proxy: %w", err)
	}
	if logger == nil {
		logger = func(string, ...any) {}
	}
	f := &proxyAuthForwarder{upstream: u.Host, auth: auth, logger: logger}
	srv := &http.Server{Handler: f}
	go func() {
		if serr := srv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
			logger("proxy-auth forwarder: %v", serr)
		}
	}()
	return "http://" + ln.Addr().String(), func() { _ = srv.Close() }, nil
}

// proxyAuthForwarder is a minimal forwarding proxy that adds a fixed
// Proxy-Authorization header before relaying to the upstream proxy.
type proxyAuthForwarder struct {
	upstream string // host:port of the credentialed upstream proxy
	auth     string // "Basic <base64(user:pass)>"
	logger   func(string, ...any)
}

func (f *proxyAuthForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		f.handleConnect(w, r)
		return
	}
	f.handleHTTP(w, r)
}

// handleConnect tunnels HTTPS: it performs the CONNECT handshake with the
// upstream proxy (adding auth), then splices the two connections.
func (f *proxyAuthForwarder) handleConnect(w http.ResponseWriter, r *http.Request) {
	up, err := net.DialTimeout("tcp", f.upstream, 30*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req := "CONNECT " + r.Host + " HTTP/1.1\r\n" +
		"Host: " + r.Host + "\r\n" +
		"Proxy-Authorization: " + f.auth + "\r\n" +
		"Proxy-Connection: Keep-Alive\r\n\r\n"
	if _, err := up.Write([]byte(req)); err != nil {
		_ = up.Close()
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	upReader := bufio.NewReader(up)
	resp, err := http.ReadResponse(upReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = up.Close()
		http.Error(w, "upstream proxy handshake: "+err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = up.Close()
		http.Error(w, "upstream proxy: "+resp.Status, http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = up.Close()
		_ = client.Close()
		return
	}
	// upReader may hold bytes already read past the CONNECT response, so relay
	// via it (not the raw conn) for the upstream->client direction.
	go func() {
		_, _ = io.Copy(up, client)
		_ = up.Close()
	}()
	_, _ = io.Copy(client, upReader)
	_ = client.Close()
	_ = up.Close()
}

// handleHTTP forwards a plain-HTTP proxied request (absolute-form URL) to the
// upstream proxy with injected auth and relays the response.
func (f *proxyAuthForwarder) handleHTTP(w http.ResponseWriter, r *http.Request) {
	up, err := net.DialTimeout("tcp", f.upstream, 30*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = up.Close() }()

	r.Header.Set("Proxy-Authorization", f.auth)
	r.Header.Set("Connection", "close")
	if err := r.WriteProxy(up); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
