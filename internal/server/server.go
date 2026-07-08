// Package server exposes the control plane over HTTP: sandbox lifecycle,
// governed tool calls, approvals, audit endpoints, a terminal WebSocket, and
// optionally the web dashboard. Every tool call goes through
// controlplane.Manager, so governance is always enforced.
package server

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Runewardd/runeward/internal/authz"
	"github.com/Runewardd/runeward/internal/controlplane"
	"github.com/Runewardd/runeward/internal/obs"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

// maxRequestBodyBytes caps the size of a request body the control plane will
// read, so an unauthenticated (or authenticated) peer cannot exhaust memory by
// streaming an unbounded body into decodeJSON.
const maxRequestBodyBytes = 16 << 20 // 16 MiB

// Server is the control-plane HTTP surface.
type Server struct {
	mgr       *controlplane.Manager
	dashboard http.Handler
	logger    *slog.Logger
	upgrader  websocket.Upgrader
	tickets   apiTicketStore

	// AuthToken, when non-empty, requires every request (except /healthz) to
	// present it as a bearer token. Empty disables authentication. Ignored when
	// Authz is set.
	AuthToken string

	// Authz, when set, enables multi-principal RBAC: each request's bearer token
	// is resolved to a named principal with per-profile launch and approval
	// permissions. Takes precedence over AuthToken.
	Authz *authz.Store

	// MCP, when set, is mounted at /mcp alongside the REST API.
	MCP http.Handler
}

// principalCtxKey keys the authenticated principal in a request context.
type principalCtxKey struct{}

type apiTicketStore struct {
	mu   sync.Mutex
	byID map[string]apiTicket
}

type apiTicket struct {
	Scope     ticketScope
	Principal *authz.Principal
	ExpiresAt time.Time
}

type ticketScope struct {
	Kind      string
	SandboxID string
	Path      string
}

const (
	ticketKindTerminal = "terminal"
	ticketKindDownload = "download"
)

// principalFrom returns the RBAC principal attached to the request, or nil when
// RBAC is not configured (legacy single-token / open mode).
func principalFrom(ctx context.Context) *authz.Principal {
	p, _ := ctx.Value(principalCtxKey{}).(*authz.Principal)
	return p
}

// New builds a Server over mgr. dashboard, when non-nil, is mounted at "/";
// logger may be nil.
func New(mgr *controlplane.Manager, dashboard http.Handler, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		mgr:       mgr,
		dashboard: dashboard,
		logger:    logger,
		upgrader:  websocket.Upgrader{CheckOrigin: sameOrigin},
	}
}

// sameOrigin guards the terminal WebSocket against cross-site hijacking: a
// browser tab on another site must not be able to open a shell into a sandbox.
// Requests with no Origin (native tooling like curl/websocat) are allowed;
// browser requests must carry an Origin whose host matches the Host header.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// Handler returns the routed http.Handler for the control plane.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /metrics", obs.MetricsHandler())

	mux.HandleFunc("GET /v1/whoami", s.handleWhoami)
	mux.HandleFunc("GET /v1/profiles", s.handleListProfiles)
	mux.HandleFunc("POST /v1/tickets", s.handleCreateTicket)
	mux.HandleFunc("POST /v1/policy/simulate", s.handlePolicySimulate)

	mux.HandleFunc("POST /v1/sandboxes", s.handleCreateSandbox)
	mux.HandleFunc("GET /v1/sandboxes", s.handleListSandboxes)
	mux.HandleFunc("GET /v1/sandboxes/{id}", s.handleGetSandbox)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", s.handleKillSandbox)

	mux.HandleFunc("POST /v1/sandboxes/{id}/shell/exec", s.handleShell)
	mux.HandleFunc("POST /v1/sandboxes/{id}/browser", s.handleBrowser)
	mux.HandleFunc("POST /v1/sandboxes/{id}/browser/sessions", s.handleBrowserOpen)
	mux.HandleFunc("POST /v1/sandboxes/{id}/browser/sessions/{sid}/act", s.handleBrowserAct)
	mux.HandleFunc("DELETE /v1/sandboxes/{id}/browser/sessions/{sid}", s.handleBrowserClose)
	mux.HandleFunc("POST /v1/sandboxes/{id}/code/python", s.handlePython)
	mux.HandleFunc("POST /v1/sandboxes/{id}/code/node", s.handleNode)
	mux.HandleFunc("POST /v1/sandboxes/{id}/file/read", s.handleFileRead)
	mux.HandleFunc("POST /v1/sandboxes/{id}/file/write", s.handleFileWrite)
	mux.HandleFunc("POST /v1/sandboxes/{id}/file/list", s.handleFileList)
	mux.HandleFunc("POST /v1/sandboxes/{id}/file/search", s.handleFileSearch)
	mux.HandleFunc("POST /v1/sandboxes/{id}/usage", s.handleReportUsage)
	mux.HandleFunc("GET /v1/sandboxes/{id}/egress", s.handleEgressLog)

	mux.HandleFunc("POST /v1/fleets", s.handleCreateFleet)
	mux.HandleFunc("GET /v1/fleets", s.handleListFleets)
	mux.HandleFunc("GET /v1/fleets/{id}", s.handleGetFleet)
	mux.HandleFunc("DELETE /v1/fleets/{id}", s.handleKillFleet)
	mux.HandleFunc("GET /v1/fleets/{id}/tasks", s.handleListTasks)
	mux.HandleFunc("POST /v1/fleets/{id}/tasks", s.handleAddTask)
	mux.HandleFunc("POST /v1/fleets/{id}/claim", s.handleClaimTask)
	mux.HandleFunc("POST /v1/fleets/{id}/tasks/{taskID}/complete", s.handleCompleteTask)
	mux.HandleFunc("POST /v1/fleets/{id}/tasks/{taskID}/fail", s.handleFailTask)
	mux.HandleFunc("POST /v1/fleets/{id}/tasks/{taskID}/heartbeat", s.handleHeartbeatTask)

	mux.HandleFunc("POST /v1/sandboxes/{id}/snapshot", s.handleSnapshot)
	mux.HandleFunc("GET /v1/snapshots", s.handleListSnapshots)
	mux.HandleFunc("POST /v1/snapshots/{id}/restore", s.handleRestoreSnapshot)

	mux.HandleFunc("GET /v1/sandboxes/{id}/audit", s.handleAudit)
	mux.HandleFunc("GET /v1/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("GET /v1/audit/pubkey", s.handleAuditPubKey)
	mux.HandleFunc("GET /v1/audit/export", s.handleAuditExport)

	mux.HandleFunc("GET /v1/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /v1/approvals/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST /v1/approvals/{id}/deny", s.handleDeny)

	mux.HandleFunc("GET /v1/sandboxes/{id}/terminal", s.handleTerminal)
	mux.HandleFunc("POST /v1/sandboxes/{id}/terminal-ticket", s.handleTerminalTicket)

	if s.MCP != nil {
		mux.Handle("/mcp", s.MCP)
		mux.Handle("/mcp/", s.MCP)
	}

	if s.dashboard != nil {
		mux.Handle("/", s.dashboard)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{
				"service": "runeward control plane",
				"docs":    "/v1/profiles, /v1/sandboxes, /v1/approvals, /v1/audit/verify",
			})
		})
	}

	h := s.authenticate(s.ownershipGuard(csrfGuard(limitBody(mux))))
	if lim := newRateLimiter(); lim != nil {
		h = lim.middleware(h)
	}
	return logRequests(s.logger, recoverPanic(s.logger, h))
}

// authenticate wraps next with the active authentication scheme: multi-principal
// RBAC when Authz is set (each token maps to a named principal), otherwise the
// legacy single-token check. When neither is configured the server runs in open
// mode with no authentication.
//
// The static dashboard shell (index.html, app.js, style.css, images) is always
// served unauthenticated so a browser can load the SPA and present its login
// form; the API surface (/v1, /mcp, /metrics) and the terminal WebSocket always
// require credentials.
func (s *Server) authenticate(next http.Handler) http.Handler {
	if s.Authz == nil && s.AuthToken == "" {
		return next
	}
	want := []byte(s.AuthToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || s.publicDashboardAsset(r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.Authz != nil {
			if tp, ok, attempted := s.consumeRequestTicket(r); attempted {
				if !ok {
					w.Header().Set("WWW-Authenticate", "Bearer")
					writeError(w, http.StatusUnauthorized, "unauthorized: invalid or expired ticket")
					return
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, tp)))
				return
			}
			p, ok := s.Authz.Identify(presentedToken(r, isTerminalPath(r.URL.Path)))
			if !ok {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, http.StatusUnauthorized, "unauthorized: unknown or missing API token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, p)))
			return
		}
		if _, ok, attempted := s.consumeRequestTicket(r); attempted {
			if !ok {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, http.StatusUnauthorized, "unauthorized: invalid or expired ticket")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !tokenMatches(r, want, isTerminalPath(r.URL.Path)) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid API token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// publicDashboardAsset reports whether r targets the static dashboard shell
// rather than the API. These files carry no secrets and must load without a
// token so the browser can render the login screen; anything under /v1, /mcp,
// or /metrics stays protected. Only ever true when a dashboard is mounted.
func (s *Server) publicDashboardAsset(r *http.Request) bool {
	if s.dashboard == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	p := r.URL.Path
	switch {
	case p == "/v1" || strings.HasPrefix(p, "/v1/"):
		return false
	case p == "/mcp" || strings.HasPrefix(p, "/mcp/"):
		return false
	case p == "/metrics":
		return false
	}
	return true
}

// ownershipGuard enforces per-principal sandbox access under RBAC: a non-admin
// principal may only touch sandboxes it owns. It runs after authenticate (so
// the principal is in context) and inspects sandbox-scoped paths
// (/v1/sandboxes/{id}[/...]). Unknown or other-owned sandboxes return 404 so a
// principal can't even probe for the existence of another principal's
// sandboxes. Open/legacy mode (no principal) and admins are unrestricted.
func (s *Server) ownershipGuard(next http.Handler) http.Handler {
	const sandboxPrefix = "/v1/sandboxes/"
	const fleetPrefix = "/v1/fleets/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		if p == nil || p.Admin {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, sandboxPrefix) {
			rest := strings.TrimPrefix(r.URL.Path, sandboxPrefix)
			id := rest
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				id = rest[:i]
			}
			if id != "" {
				if owner, ok := s.mgr.SandboxOwner(id); !ok || owner != p.Name {
					writeError(w, http.StatusNotFound, "sandbox not found")
					return
				}
			}
		}
		if strings.HasPrefix(r.URL.Path, fleetPrefix) {
			rest := strings.TrimPrefix(r.URL.Path, fleetPrefix)
			id := rest
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				id = rest[:i]
			}
			if id != "" && !s.fleetOwnedBy(id, p.Name) {
				writeError(w, http.StatusNotFound, "fleet not found")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/snapshots/") && strings.HasSuffix(r.URL.Path, "/restore") {
			id := strings.TrimPrefix(r.URL.Path, "/v1/snapshots/")
			id = strings.TrimSuffix(id, "/restore")
			if !s.snapshotVisibleTo(p, id) {
				writeError(w, http.StatusNotFound, "snapshot not found")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/audit/") {
			if r.URL.Path == "/v1/audit/export" {
				writeError(w, http.StatusForbidden, "not authorized to export audit bundle")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/approvals") && !p.MayApprove() {
			writeError(w, http.StatusForbidden, "not authorized to view approvals")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recoverPanic converts a panicking handler into a logged, generic 500 so a
// bug can't leak a stack trace or internal detail to the client or crash the
// server.
func recoverPanic(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if logger != nil {
					logger.Error("panic serving request", "method", r.Method, "path", r.URL.Path, "panic", rec)
				}
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// csrfGuard rejects state-changing requests whose Origin header (when present)
// doesn't match the Host. Non-browser clients (curl, SDKs) send no Origin and
// pass through; a malicious cross-site page can't drive the API even if it
// somehow has a token, because browsers always attach Origin on such requests.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Safe methods; the terminal WebSocket upgrade has its own origin check.
		default:
			if origin := r.Header.Get("Origin"); origin != "" {
				if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
					writeError(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a per-client-IP token-bucket limiter.
type rateLimiter struct {
	rps   rate.Limit
	burst int
	mu    sync.Mutex
	byIP  map[string]*rate.Limiter
}

// newRateLimiter builds a limiter from RUNEWARD_RATE_LIMIT (requests/sec per
// client IP). Unset/zero disables rate limiting entirely.
func newRateLimiter() *rateLimiter {
	v := strings.TrimSpace(os.Getenv("RUNEWARD_RATE_LIMIT"))
	if v == "" {
		return nil
	}
	rps, err := strconv.ParseFloat(v, 64)
	if err != nil || rps <= 0 {
		return nil
	}
	burst := int(rps * 2)
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{rps: rate.Limit(rps), burst: burst, byIP: make(map[string]*rate.Limiter)}
}

func (l *rateLimiter) limiterFor(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.byIP[ip]
	if !ok {
		lim = rate.NewLimiter(l.rps, l.burst)
		l.byIP[ip] = lim
	}
	return lim
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !l.limiterFor(ip).Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the control plane on addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// TokenAuth wraps next with bearer-token authentication. When token is empty,
// authentication is disabled and next is returned unchanged. /healthz is always
// exempt so liveness probes work without credentials. The token may be
// presented as "Authorization: Bearer <token>", an "X-Runeward-Token" header,
// or a "token" query parameter only for terminal WebSocket compatibility.
func TokenAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if !tokenMatches(r, want, isTerminalPath(r.URL.Path)) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized: missing or invalid API token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// presentedToken extracts the caller's token from the Authorization bearer
// header, the X-Runeward-Token header, and optionally the ?token= query param
// when allowQuery is true.
func presentedToken(r *http.Request, allowQuery bool) string {
	if h := r.Header.Get("Authorization"); h != "" {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if h := r.Header.Get("X-Runeward-Token"); h != "" {
		return strings.TrimSpace(h)
	}
	if !allowQuery {
		return ""
	}
	return r.URL.Query().Get("token")
}

// tokenMatches reports whether r carries the expected token, using a
// constant-time comparison to avoid leaking it via timing.
func tokenMatches(r *http.Request, want []byte, allowQuery bool) bool {
	got := presentedToken(r, allowQuery)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), want) == 1
}

func isTerminalPath(path string) bool {
	const prefix = "/v1/sandboxes/"
	const suffix = "/terminal"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	rest := strings.TrimPrefix(path, prefix)
	id := strings.TrimSuffix(rest, suffix)
	return id != ""
}

func terminalSandboxID(path string) (string, bool) {
	if !isTerminalPath(path) {
		return "", false
	}
	rest := strings.TrimPrefix(path, "/v1/sandboxes/")
	id := strings.TrimSuffix(rest, "/terminal")
	return id, id != ""
}

func (s *Server) consumeRequestTicket(r *http.Request) (*authz.Principal, bool, bool) {
	scope := ticketScope{Kind: ticketKindDownload}
	if sandboxID, ok := terminalSandboxID(r.URL.Path); ok {
		scope = ticketScope{Kind: ticketKindTerminal, SandboxID: sandboxID}
	}
	return s.consumeTicket(r, scope)
}

func (s *Server) consumeTicket(r *http.Request, want ticketScope) (*authz.Principal, bool, bool) {
	ticketID := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if ticketID == "" {
		return nil, false, false
	}
	s.tickets.mu.Lock()
	defer s.tickets.mu.Unlock()
	if s.tickets.byID == nil {
		return nil, false, true
	}
	t, ok := s.tickets.byID[ticketID]
	if !ok {
		return nil, false, true
	}
	delete(s.tickets.byID, ticketID)
	if time.Now().After(t.ExpiresAt) {
		return nil, false, true
	}
	if t.Scope.Kind != want.Kind {
		return nil, false, true
	}
	switch want.Kind {
	case ticketKindTerminal:
		if t.Scope.SandboxID == "" || t.Scope.SandboxID != want.SandboxID {
			return nil, false, true
		}
	case ticketKindDownload:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return nil, false, true
		}
		if t.Scope.Path != "" && t.Scope.Path != r.URL.Path {
			return nil, false, true
		}
	}
	return t.Principal, true, true
}

func (s *Server) issueTicket(scope ticketScope, p *authz.Principal, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	switch scope.Kind {
	case ticketKindTerminal:
		if strings.TrimSpace(scope.SandboxID) == "" {
			return "", time.Time{}, errors.New("terminal ticket requires sandbox scope")
		}
	case ticketKindDownload:
	default:
		return "", time.Time{}, errors.New("unsupported ticket kind")
	}
	var raw [16]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	id := hex.EncodeToString(raw[:])
	expires := time.Now().Add(ttl)
	s.tickets.mu.Lock()
	defer s.tickets.mu.Unlock()
	if s.tickets.byID == nil {
		s.tickets.byID = make(map[string]apiTicket)
	}
	s.tickets.byID[id] = apiTicket{
		Scope:     scope,
		Principal: p,
		ExpiresAt: expires,
	}
	return id, expires, nil
}

func (s *Server) issueTerminalTicket(sandboxID string, p *authz.Principal, ttl time.Duration) (string, time.Time, error) {
	return s.issueTicket(ticketScope{Kind: ticketKindTerminal, SandboxID: sandboxID}, p, ttl)
}

func (s *Server) fleetOwnedBy(id, owner string) bool {
	v, ok := s.mgr.FleetView(id)
	if !ok || strings.TrimSpace(owner) == "" {
		return false
	}
	if v.Owner != "" {
		return v.Owner == owner
	}
	if len(v.Sandboxes) == 0 {
		return false
	}
	for _, sandboxID := range v.Sandboxes {
		sandboxOwner, ok := s.mgr.SandboxOwner(sandboxID)
		if !ok || sandboxOwner != owner {
			return false
		}
	}
	return true
}

func (s *Server) snapshotVisibleTo(p *authz.Principal, id string) bool {
	for _, ref := range s.mgr.ListSnapshots() {
		if ref.ID != id {
			continue
		}
		return p.CanLaunch(ref.Profile)
	}
	return false
}

// limitBody caps every request body at maxRequestBodyBytes to bound memory use.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeServerError responds with a generic 500 and a correlation id, logging
// the real error server-side. Internal failures (backend/filesystem errors)
// can embed host paths or other detail that must not leak to API callers, so
// only the id is returned; operators correlate it against the logs.
func writeServerError(w http.ResponseWriter, logger *slog.Logger, err error) {
	// Caller-actionable errors (bad input, missing resource) carry a message
	// that is safe to return, so surface them as 4xx instead of an opaque 500.
	var ce *controlplane.ClientError
	if errors.As(err, &ce) {
		status := http.StatusBadRequest
		if ce.NotFound {
			status = http.StatusNotFound
		}
		writeError(w, status, ce.Error())
		return
	}
	id := newRequestID()
	if logger != nil {
		logger.Error("internal error serving request", "request_id", id, "error", err)
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error":      "internal server error",
		"request_id": id,
	})
}

// newRequestID returns a short random hex id for correlating a client-visible
// error with a server log line.
func newRequestID() string {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// logRequests is a structured access-log middleware. High-frequency probe
// endpoints (/metrics, /healthz) are not logged to avoid drowning the log.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.URL.Path == "/metrics" || r.URL.Path == "/healthz" {
			return
		}
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap exposes the underlying ResponseWriter to http.ResponseController.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack lets the WebSocket upgrader take over the connection despite the
// access-log wrapper.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}
