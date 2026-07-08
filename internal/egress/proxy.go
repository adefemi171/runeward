package egress

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dialTimeout bounds dials to origins and CONNECT targets.
const dialTimeout = 30 * time.Second

// Proxy is a forward proxy that enforces Policy on CONNECT tunnels (HTTPS)
// and plain absolute-URI HTTP requests.
type Proxy struct {
	Policy Policy
	// SandboxID associates decisions with a sandbox for dashboard egress logs.
	SandboxID string
	// Logger receives allow/deny decisions; nil discards them.
	Logger *log.Logger
	// AuthUser/AuthPass, when both set, require Proxy-Authorization (HTTP Basic)
	// on every request. This keeps a proxy bound on a shared interface (e.g. the
	// host proxy reachable via host.docker.internal) from being used by other
	// local/LAN processes.
	AuthUser string
	AuthPass string
	// transport forwards plain HTTP requests; nil falls back to the default.
	transport http.RoundTripper
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Logger != nil {
		p.Logger.Printf(format, args...)
	}
}

func (p *Proxy) sandboxID() string {
	if id := strings.TrimSpace(p.SandboxID); id != "" {
		return id
	}
	if p.Logger != nil {
		return sandboxIDFromLoggerPrefix(p.Logger.Prefix())
	}
	return ""
}

func (p *Proxy) recordDecision(host, ip string, allow bool, reason string) {
	RecordDecision(p.sandboxID(), host, ip, allow, reason)
}

// authOK reports whether r satisfies the configured proxy credentials. When no
// credentials are configured it always passes.
func (p *Proxy) authOK(r *http.Request) bool {
	if p.AuthUser == "" && p.AuthPass == "" {
		return true
	}
	user, pass, ok := parseProxyBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(p.AuthUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(p.AuthPass)) == 1
	return userOK && passOK
}

// Handler returns an [http.Handler] implementing the forward proxy.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.authOK(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="runeward-egress"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
		if r.Method == http.MethodConnect {
			p.handleConnect(w, r)
			return
		}
		p.handleHTTP(w, r)
	})
}

// handleConnect checks a CONNECT target against the policy, then hijacks the
// client connection and splices it to the target.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host // for CONNECT this is the "host:port" authority
	host, port, err := hostWithDefaultPort(target, "443")
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	pinnedTarget := net.JoinHostPort(host, port)
	if ip := net.ParseIP(host); ip != nil {
		if !p.Policy.AllowAddr(pinnedTarget) {
			p.logf("egress: DENY CONNECT %s", target)
			p.recordDecision(host, ip.String(), false, "blocked by egress policy")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		pinnedTarget = net.JoinHostPort(ip.String(), port)
	} else {
		if !p.Policy.AllowListedHostname(host) {
			p.logf("egress: DENY CONNECT %s", target)
			p.recordDecision(host, "", false, "hostname not allowlisted")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		pinnedTarget, err = pinnedAddrForHost(host, port, nil)
		if err != nil {
			p.logf("egress: DENY CONNECT %s (resolve failed: %v)", target, err)
			p.recordDecision(host, "", false, "hostname resolution failed")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}
	if pinnedTarget == "" {
		p.logf("egress: DENY CONNECT %s", target)
		p.recordDecision(host, "", false, "target pinning failed")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	pinnedIP, _, _ := net.SplitHostPort(pinnedTarget)

	upstream, err := net.DialTimeout("tcp", pinnedTarget, dialTimeout)
	if err != nil {
		p.logf("egress: ALLOW CONNECT %s (dial=%s failed: %v)", target, pinnedTarget, err)
		p.recordDecision(host, pinnedIP, true, "allowed by policy (dial failed)")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.logf("egress: ALLOW CONNECT %s (dial=%s)", target, pinnedTarget)
	p.recordDecision(host, pinnedIP, true, "allowed by egress policy")

	// Splice both directions; return once both are done.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
	<-done
}

// handleHTTP checks a plain forward-proxy request against the policy and, if
// allowed, forwards it to the origin.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// A forward-proxy request carries an absolute URL with a host set.
	authority := r.URL.Host
	if authority == "" {
		authority = r.Host
	}
	host, port, err := hostWithDefaultPort(authority, defaultPortForScheme(r.URL))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	allowed := false
	pinnedHostport := net.JoinHostPort(host, port)
	if ip := net.ParseIP(host); ip != nil {
		allowed = p.Policy.AllowAddr(pinnedHostport)
		pinnedHostport = net.JoinHostPort(ip.String(), port)
	} else {
		allowed = p.Policy.AllowListedHostname(host)
		if allowed {
			pinnedHostport, err = pinnedAddrForHost(host, port, nil)
			if err != nil {
				allowed = false
			}
		}
	}
	if !allowed {
		p.logf("egress: DENY HTTP %s %s", r.Method, authority)
		p.recordDecision(host, "", false, "blocked by egress policy")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	pinnedIP, _, _ := net.SplitHostPort(pinnedHostport)
	p.logf("egress: ALLOW HTTP %s %s (dial=%s)", r.Method, authority, pinnedHostport)
	p.recordDecision(host, pinnedIP, true, "allowed by egress policy")

	transport := p.transport
	if transport == nil {
		transport = &PinnedTransport{}
	} else if base, ok := transport.(*http.Transport); ok {
		transport = &PinnedTransport{Base: base}
	} else {
		p.logf("egress: DENY HTTP %s %s (unsupported transport for pinning)", r.Method, authority)
		p.recordDecision(host, pinnedIP, false, "unsupported transport for pinning")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// RequestURI must be empty on client requests.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL == nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	outReq.URL = cloneURL(outReq.URL)
	outReq.URL.Host = pinnedHostport
	if outReq.Host == "" {
		outReq.Host = authority
	}
	if strings.EqualFold(outReq.URL.Scheme, "https") {
		// Preserve SNI/hostname verification while dialing the pinned IP.
		outReq = outReq.WithContext(context.WithValue(outReq.Context(), pinnedServerNameKey{}, host))
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

type pinnedServerNameKey struct{}

func defaultPortForScheme(u *url.URL) string {
	if u != nil && strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return nil
	}
	c := *in
	return &c
}

// PinnedTransport wraps base and forces dials to outReq.URL.Host (already pinned).
// It keeps TLS ServerName from request context when provided.
type PinnedTransport struct {
	Base *http.Transport
}

func (t *PinnedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			base = dt.Clone()
		} else {
			return nil, fmt.Errorf("default transport is not *http.Transport")
		}
	} else {
		base = base.Clone()
	}
	pinnedAddr := r.URL.Host
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := &net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, network, pinnedAddr)
	}
	if name, _ := r.Context().Value(pinnedServerNameKey{}).(string); name != "" {
		if base.TLSClientConfig == nil {
			base.TLSClientConfig = &tls.Config{ServerName: name}
		} else {
			base.TLSClientConfig = base.TLSClientConfig.Clone()
			base.TLSClientConfig.ServerName = name
		}
	}
	return base.RoundTrip(r)
}

// parseProxyBasicAuth parses a "Basic base64(user:pass)" Proxy-Authorization
// header value.
func parseProxyBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(dec), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ListenAndServe serves the proxy handler on addr until an error occurs.
func (p *Proxy) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: p.Handler(),
	}
	return srv.ListenAndServe()
}
