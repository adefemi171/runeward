package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/adefemi171/runeward/internal/backend"
	"github.com/gorilla/websocket"
)

// controlMessage is a JSON control frame from the browser terminal (e.g.
// resize). Anything else on the socket is raw keystroke input.
type controlMessage struct {
	Type string `json:"type"`
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
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
		s.logger.Printf("terminal: upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	pr, pw := io.Pipe()
	resize := make(chan backend.TermSize, 1)
	out := &wsWriter{conn: conn}

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
