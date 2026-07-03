// Package server exposes the control plane over HTTP: sandbox lifecycle,
// governed tool calls, approvals, audit endpoints, a terminal WebSocket, and
// optionally the web dashboard. Every tool call goes through
// controlplane.Manager, so governance is always enforced.
package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/adefemi171/runeward/internal/controlplane"
	"github.com/gorilla/websocket"
)

// Server is the control-plane HTTP surface.
type Server struct {
	mgr       *controlplane.Manager
	dashboard http.Handler
	logger    *log.Logger
	upgrader  websocket.Upgrader

	// MCP, when set, is mounted at /mcp alongside the REST API.
	MCP http.Handler
}

// New builds a Server over mgr. dashboard, when non-nil, is mounted at "/";
// logger may be nil.
func New(mgr *controlplane.Manager, dashboard http.Handler, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
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

	mux.HandleFunc("GET /v1/profiles", s.handleListProfiles)

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

	return logRequests(s.logger, mux)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// logRequests is a minimal access-log middleware.
func logRequests(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		logger.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
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
