package egress

import (
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// dialTimeout bounds dials to origins and CONNECT targets.
const dialTimeout = 30 * time.Second

// Proxy is a forward proxy that enforces Policy on CONNECT tunnels (HTTPS)
// and plain absolute-URI HTTP requests.
type Proxy struct {
	Policy Policy
	// Logger receives allow/deny decisions; nil discards them.
	Logger *log.Logger
	// transport forwards plain HTTP requests; nil falls back to the default.
	transport http.RoundTripper
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Logger != nil {
		p.Logger.Printf(format, args...)
	}
}

// Handler returns an [http.Handler] implementing the forward proxy.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if !p.Policy.AllowAddr(target) {
		p.logf("egress: DENY CONNECT %s", target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		p.logf("egress: ALLOW CONNECT %s (dial failed: %v)", target, err)
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
	p.logf("egress: ALLOW CONNECT %s", target)

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
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if !p.Policy.AllowAddr(host) {
		p.logf("egress: DENY HTTP %s %s", r.Method, host)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	p.logf("egress: ALLOW HTTP %s %s", r.Method, host)

	transport := p.transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	// RequestURI must be empty on client requests.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

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
