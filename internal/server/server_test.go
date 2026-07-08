package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Runewardd/runeward/internal/authz"
	"github.com/Runewardd/runeward/internal/controlplane"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	return newTestServerWithToken(t, "")
}

func newTestServerWithToken(t *testing.T, token string) http.Handler {
	t.Helper()
	t.Setenv("RUNEWARD_STATE_DIR", t.TempDir())
	mgr, err := controlplane.New(t.TempDir())
	if err != nil {
		t.Fatalf("controlplane.New: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	srv := New(mgr, nil, nil)
	srv.AuthToken = token
	return srv.Handler()
}

func newTestServerWithRBAC(t *testing.T) http.Handler {
	t.Helper()
	t.Setenv("RUNEWARD_STATE_DIR", t.TempDir())
	mgr, err := controlplane.New(t.TempDir())
	if err != nil {
		t.Fatalf("controlplane.New: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	p := filepath.Join(t.TempDir(), "authz.json")
	cfg := `{
		"principals":[
			{"name":"admin","token":"tok-admin","admin":true},
			{"name":"alice","token":"tok-alice","allowed_profiles":["team-*"]},
			{"name":"reviewer","token":"tok-reviewer","can_approve":true,"allowed_profiles":["team-*"]}
		]
	}`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write authz config: %v", err)
	}
	store, err := authz.Load(p)
	if err != nil {
		t.Fatalf("authz.Load: %v", err)
	}
	srv := New(mgr, nil, nil)
	srv.Authz = store
	return srv.Handler()
}

func TestAuthTokenRequired(t *testing.T) {
	h := newTestServerWithToken(t, "s3cret")

	// No token: rejected.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rr.Code)
	}

	// Wrong token: rejected.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.Header.Set("Authorization", "Bearer nope")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rr.Code)
	}

	// Correct bearer token: allowed.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d, want 200", rr.Code)
	}

	// Query-param token is no longer accepted for normal REST requests.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes?token=s3cret", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("query token on REST: status = %d, want 401", rr.Code)
	}

	// Query-param token remains accepted for terminal WebSocket compatibility.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/nope/terminal?token=s3cret", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("query token on terminal: status = %d, want 404", rr.Code)
	}

	// /healthz is always exempt.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz: status = %d, want 200", rr.Code)
	}
}

func TestHealth(t *testing.T) {
	h := newTestServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %q", body["status"])
	}
}

func TestAuditVerifyEmpty(t *testing.T) {
	h := newTestServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/audit/verify", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("empty ledger should verify ok, got %v", body)
	}
}

func TestApprovalsEmpty(t *testing.T) {
	h := newTestServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/approvals", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"approvals":[]`) {
		t.Fatalf("expected empty approvals array, got %s", rr.Body.String())
	}
}

func TestCreateSandboxUnknownProfile(t *testing.T) {
	h := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"profile":"does-not-exist"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestUnknownSandbox404(t *testing.T) {
	h := newTestServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestRBACApprovalsInboxRequiresApprovalPermission(t *testing.T) {
	h := newTestServerWithRBAC(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer tok-alice")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestRBACAuditExportRequiresAdmin(t *testing.T) {
	h := newTestServerWithRBAC(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/audit/export", nil)
	req.Header.Set("Authorization", "Bearer tok-reviewer")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestCreateFleetEnforcesCanLaunch(t *testing.T) {
	h := newTestServerWithRBAC(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/fleets", strings.NewReader(`{"profile":"ops-prod"}`))
	req.Header.Set("Authorization", "Bearer tok-alice")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestTaskOwnerFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/fleets/f/tasks/t/complete", nil)
	if _, err := taskOwnerFromRequest(req, ""); err == nil {
		t.Fatalf("expected error for empty unauthenticated owner")
	}
	if owner, err := taskOwnerFromRequest(req, "worker-a"); err != nil || owner != "worker-a" {
		t.Fatalf("owner = %q, err = %v, want worker-a,nil", owner, err)
	}
	p := &authz.Principal{Name: "alice"}
	ctx := context.WithValue(req.Context(), principalCtxKey{}, p)
	req = req.WithContext(ctx)
	if owner, err := taskOwnerFromRequest(req, "worker-a"); err != nil || owner != "alice" {
		t.Fatalf("owner = %q, err = %v, want alice,nil", owner, err)
	}
}

func TestTerminalTicketSingleUse(t *testing.T) {
	h := newTestServerWithToken(t, "s3cret")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb1/terminal-ticket", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want 201", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&body); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	ticket, _ := body["ticket"].(string)
	if strings.TrimSpace(ticket) == "" {
		t.Fatalf("ticket was empty")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb1/terminal?ticket="+ticket, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("first use status = %d, want 404", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb1/terminal?ticket="+ticket, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("second use status = %d, want 401", rr.Code)
	}
}

func TestGeneralDownloadTicketSingleUse(t *testing.T) {
	h := newTestServerWithToken(t, "s3cret")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tickets", strings.NewReader(`{"kind":"download","path":"/v1/audit/export"}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want 201", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&body); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	ticket, _ := body["ticket"].(string)
	if strings.TrimSpace(ticket) == "" {
		t.Fatalf("ticket was empty")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/audit/export?ticket="+ticket, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("first use status = %d, want 200", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/audit/export?ticket="+ticket, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("second use status = %d, want 401", rr.Code)
	}
}

func TestPolicySimulateBuiltin(t *testing.T) {
	h := newTestServer(t)
	body := `{
		"profile": {
			"host": {"type":"container","image":"ghcr.io/runewardd/runeward-sandbox:latest","workdir":"/workspace"},
			"network": {"default":"allow"},
			"policy":[
				{"tool":"shell","match":"rm *","verdict":"deny","reason":"dangerous"},
				{"tool":"*","match":"*","verdict":"allow"}
			]
		},
		"actions":[
			{"name":"deny rm","tool":"shell","command":"rm -rf /"},
			{"name":"allow ls","tool":"shell","command":"ls -la"}
		]
	}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/simulate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Results []struct {
			Name    string `json:"name"`
			Verdict string `json:"verdict"`
			Trace   []any  `json:"trace"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(resp.Results))
	}
	if resp.Results[0].Verdict != "deny" {
		t.Fatalf("first verdict = %q, want deny", resp.Results[0].Verdict)
	}
	if len(resp.Results[0].Trace) == 0 {
		t.Fatalf("expected trace entries")
	}
	if resp.Results[1].Verdict != "allow" {
		t.Fatalf("second verdict = %q, want allow", resp.Results[1].Verdict)
	}
}
