package browser

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeCDPServer speaks just enough CDP to exercise the client.
func fakeCDPServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var req struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			if json.Unmarshal(data, &req) != nil {
				continue
			}
			switch req.Method {
			case "Page.enable":
				_ = conn.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
			case "Page.navigate":
				_ = conn.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{"frameId": "frame-1"}})
				_ = conn.WriteJSON(map[string]any{
					"method": "Page.loadEventFired",
					"params": map[string]any{"timestamp": 1.0},
				})
			case "Runtime.evaluate":
				_ = conn.WriteJSON(map[string]any{
					"id": req.ID,
					"result": map[string]any{
						"result": map[string]any{"type": "string", "value": "canned-value"},
					},
				})
			default:
				_ = conn.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

func TestClientNavigateEvalText(t *testing.T) {
	srv := fakeCDPServer(t)

	client, err := Dial(wsURL(srv.URL))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.CallTimeout = 3 * time.Second

	if err := client.Navigate("http://example.com/", 2*time.Second); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	v, err := client.Eval("1+1")
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if v != "canned-value" {
		t.Fatalf("eval value = %q, want %q", v, "canned-value")
	}

	txt, err := client.Text()
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	if txt != "canned-value" {
		t.Fatalf("text value = %q, want %q", txt, "canned-value")
	}

	title, err := client.Title()
	if err != nil {
		t.Fatalf("title: %v", err)
	}
	if title != "canned-value" {
		t.Fatalf("title value = %q, want %q", title, "canned-value")
	}
}

func TestClientEvalError(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var req struct {
				ID int `json:"id"`
			}
			_ = json.Unmarshal(data, &req)
			_ = conn.WriteJSON(map[string]any{
				"id": req.ID,
				"result": map[string]any{
					"result": map[string]any{"type": "object"},
					"exceptionDetails": map[string]any{
						"text":      "Uncaught",
						"exception": map[string]any{"description": "ReferenceError: boom is not defined"},
					},
				},
			})
		}
	}))
	defer srv.Close()

	client, err := Dial(wsURL(srv.URL))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if _, err := client.Eval("boom"); err == nil {
		t.Fatal("expected eval error, got nil")
	}
}

func TestStringifyValue(t *testing.T) {
	cases := []struct {
		typ   string
		value string
		want  string
	}{
		{"string", `"hello"`, "hello"},
		{"number", `42`, "42"},
		{"boolean", `true`, "true"},
		{"undefined", ``, ""},
		{"object", `{"a":1}`, `{"a":1}`},
	}
	for _, tc := range cases {
		got, err := stringifyValue(tc.typ, json.RawMessage(tc.value))
		if err != nil {
			t.Fatalf("stringifyValue(%q,%q): %v", tc.typ, tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("stringifyValue(%q,%q) = %q, want %q", tc.typ, tc.value, got, tc.want)
		}
	}
}

func TestValidateNavigateURL(t *testing.T) {
	t.Setenv(envAllowPrivateNavigate, "")
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{name: "http allowed", url: "http://example.com", ok: true},
		{name: "https allowed", url: "https://example.com", ok: true},
		{name: "about blank allowed", url: "about:blank", ok: true},
		{name: "file blocked", url: "file:///etc/passwd", ok: false},
		{name: "data blocked", url: "data:text/plain,boom", ok: false},
		{name: "javascript blocked", url: "javascript:alert(1)", ok: false},
		{name: "chrome blocked", url: "chrome://version", ok: false},
		{name: "loopback blocked", url: "http://127.0.0.1:9222/json", ok: false},
		{name: "localhost blocked", url: "http://localhost:8080", ok: false},
		{name: "private blocked", url: "http://10.1.2.3", ok: false},
		{name: "link local blocked", url: "http://169.254.169.254/latest/meta-data", ok: false},
	}
	for _, tc := range cases {
		err := ValidateNavigateURL(tc.url)
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

func TestValidateNavigateURLAllowsPrivateWhenEnabled(t *testing.T) {
	t.Setenv(envAllowPrivateNavigate, "1")
	if err := ValidateNavigateURL("http://127.0.0.1:9222/json"); err != nil {
		t.Fatalf("expected private host to be allowed when override is set: %v", err)
	}
}
