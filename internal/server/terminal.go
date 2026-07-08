package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/termrec"
	"github.com/gorilla/websocket"
)

const terminalTicketTTL = 30 * time.Second

// controlMessage is a JSON control frame from the browser terminal (e.g.
// resize). Anything else on the socket is raw keystroke input.
type controlMessage struct {
	Type string `json:"type"`
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

func (s *Server) handleTerminalTicket(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := principalFrom(r.Context())
	ticket, expiresAt, err := s.issueTerminalTicket(id, p, terminalTicketTTL)
	if err != nil {
		writeServerError(w, s.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ticket":     ticket,
		"expires_at": expiresAt.UTC(),
	})
}

// handleTerminal upgrades to a WebSocket and bridges it to a sandbox PTY,
// handling {"type":"resize"} control frames along the way.
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.mgr.Sandbox(id); !ok {
		writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("terminal upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	pr, pw := io.Pipe()
	resize := make(chan backend.TermSize, 1)
	var out io.Writer = &wsWriter{conn: conn}

	// Optionally record the session (output only) to an asciinema cast for the
	// audit trail. Recording never blocks or corrupts the live stream.
	if rec := s.startRecording(id); rec != nil {
		defer rec.Close()
		out = io.MultiWriter(out, rec)
	}

	// Read loop: demux control frames from raw input.
	go func() {
		defer pw.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage {
				var cm controlMessage
				if json.Unmarshal(data, &cm) == nil && cm.Type == "resize" {
					select {
					case resize <- backend.TermSize{Rows: cm.Rows, Cols: cm.Cols}:
					default:
					}
					continue
				}
			}
			if _, err := pw.Write(data); err != nil {
				return
			}
		}
	}()

	stream := backend.PTYStream{
		Stdin:  pr,
		Stdout: out,
		TTY:    true,
		Resize: resize,
	}
	if err := s.mgr.AttachTerminal(r.Context(), id, stream); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("\r\n[runeward] terminal error: "+err.Error()+"\r\n"))
	}
	_ = pr.Close()
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"))
}

// startRecording returns a terminal recorder when RUNEWARD_RECORD_TERMINALS is
// enabled, writing an asciinema cast under the state dir; nil otherwise or on
// any setup error (recording is best-effort and must never block a session).
func (s *Server) startRecording(id string) *termrec.Recorder {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RUNEWARD_RECORD_TERMINALS"))) {
	case "1", "true", "yes", "on":
	default:
		return nil
	}
	dir := filepath.Join(s.mgr.StateDir(), "recordings")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.logger.Warn("terminal recording disabled: cannot create dir", "err", err)
		return nil
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%d.cast", id, time.Now().Unix()))
	rec, err := termrec.NewFileRecorder(path, 80, 24)
	if err != nil {
		s.logger.Warn("terminal recording disabled: cannot open cast", "err", err)
		return nil
	}
	s.logger.Info("recording terminal session", "sandbox", id, "path", path)
	return rec
}

// wsWriter adapts a WebSocket connection to an io.Writer. Writes are serialized
// because gorilla connections do not support concurrent writers.
type wsWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
