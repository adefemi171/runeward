package controlplane

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/profile"
)

// ToolResult is the governed outcome of a single tool invocation.
type ToolResult struct {
	Verdict    profile.Verdict `json:"verdict"`
	Reason     string          `json:"reason,omitempty"`
	ApprovalID string          `json:"approval_id,omitempty"`
	Pending    bool            `json:"pending,omitempty"`
	ExitCode   int             `json:"exit_code"`
	Stdout     string          `json:"stdout,omitempty"`
	Stderr     string          `json:"stderr,omitempty"`
	DurationMS int64           `json:"duration_ms"`
}

// Shell runs a command vector in the sandbox under policy control.
func (m *Manager) Shell(ctx context.Context, id string, command []string, workdir string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	if len(command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	arg := strings.Join(command, " ")
	wd := workdir
	if wd == "" {
		wd = sess.Workdir
	}
	return m.govern(ctx, sess, "shell", arg, command, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: command, Workdir: wd, Env: sess.Env})
	})
}

// Python runs a Python snippet via `python3 -c`.
func (m *Manager) Python(ctx context.Context, id, code string) (*ToolResult, error) {
	return m.runCode(ctx, id, "python", []string{"python3", "-c", code}, code)
}

// Node runs a JavaScript snippet via `node -e`.
func (m *Manager) Node(ctx context.Context, id, code string) (*ToolResult, error) {
	return m.runCode(ctx, id, "node", []string{"node", "-e", code}, code)
}

func (m *Manager) runCode(ctx context.Context, id, tool string, command []string, code string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	return m.govern(ctx, sess, tool, code, nil, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: command, Workdir: sess.Workdir, Env: sess.Env})
	})
}

// FileRead returns the contents of a file in the sandbox.
func (m *Manager) FileRead(ctx context.Context, id, path string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	resolvedPath, err := resolveFileToolPath(sess.Workdir, path)
	if err != nil {
		return nil, err
	}
	return m.govern(ctx, sess, "file.read", path, []string{path}, func(ctx context.Context) (*backend.ExecResult, error) {
		// "--" stops a path that begins with "-" from being parsed as a flag.
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: []string{"cat", "--", resolvedPath}, Workdir: sess.Workdir, Env: sess.Env})
	})
}

// FileWrite writes a file in the sandbox, creating parent directories. Content
// travels base64-encoded to stay binary-safe over the shell.
func (m *Manager) FileWrite(ctx context.Context, id, path, content string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	resolvedPath, err := resolveFileToolPath(sess.Workdir, path)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	script := fmt.Sprintf("mkdir -p \"$(dirname %s)\" && printf %%s '%s' | base64 -d > %s", shQuote(resolvedPath), b64, shQuote(resolvedPath))
	return m.govern(ctx, sess, "file.write", path, []string{path}, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: []string{"sh", "-c", script}, Workdir: sess.Workdir, Env: sess.Env})
	})
}

// FileList lists a directory in the sandbox.
func (m *Manager) FileList(ctx context.Context, id, path string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = "."
	}
	resolvedPath, err := resolveFileToolPath(sess.Workdir, path)
	if err != nil {
		return nil, err
	}
	return m.govern(ctx, sess, "file.read", path, []string{path}, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: []string{"ls", "-la", "--", resolvedPath}, Workdir: sess.Workdir, Env: sess.Env})
	})
}

// FileSearch runs a recursive grep rooted at path.
func (m *Manager) FileSearch(ctx context.Context, id, query, path string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = "."
	}
	resolvedPath, err := resolveFileToolPath(sess.Workdir, path)
	if err != nil {
		return nil, err
	}
	return m.govern(ctx, sess, "file.read", query, []string{query, path}, func(ctx context.Context) (*backend.ExecResult, error) {
		// "-e query" treats a leading-"-" query as a pattern, not a flag; "--"
		// stops the path being parsed as a flag.
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: []string{"grep", "-rn", "-e", query, "--", resolvedPath}, Workdir: sess.Workdir, Env: sess.Env})
	})
}

// Browser renders a page with headless Chromium inside the sandbox. It is
// policy-gated as tool "browser" (arg = url), and the profile's egress proxy is
// passed via --proxy-server so egress rules cover browser traffic too. mode is
// "text" (rendered DOM HTML) or "screenshot" (base64 PNG in Stdout).
func (m *Manager) Browser(ctx context.Context, id, url, mode string) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}
	script := browserScript(url, mode)
	// A screenshot's stdout is a base64 PNG; skip the text secret-scrubber so it
	// isn't masked as a high-entropy blob.
	rawStdout := mode == "screenshot"
	return m.governOut(ctx, sess, "browser", url, []string{url, mode}, rawStdout, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: []string{"sh", "-c", script}, Workdir: sess.Workdir, Env: sess.Env})
	})
}

// browserScript builds the sh -c program that renders url. It prefers the
// runeward-browser driver, which stands up a loopback forwarder that injects
// Proxy-Authorization so a credentialed egress proxy works — Chromium's own
// --proxy-server cannot carry credentials. The raw-Chromium fallback only works
// with an unauthenticated (or no) proxy and exists for older images that lack
// the driver.
//
// The egress proxy is read from the container's runtime env (HTTPS_PROXY /
// HTTP_PROXY), which the backend injects at creation and `exec` inherits, not
// from the control-plane's profile env.
func browserScript(url, mode string) string {
	renderMode := "text"
	if mode == "screenshot" {
		renderMode = "screenshot"
	}
	rbCmd := `runeward-browser render --mode ` + renderMode + ` ${PROXY:+--proxy $PROXY} ` + shQuote(url)

	find := `CHROME=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || command -v google-chrome 2>/dev/null || command -v google-chrome-stable 2>/dev/null || command -v headless-shell 2>/dev/null || echo chromium)`
	// Chromium's own sandbox needs user namespaces, which are usually
	// unavailable in a container, so --no-sandbox is the default. Under a
	// runtime that provides isolation (gVisor/Kata) or userns, operators can
	// keep Chromium's sandbox by setting RUNEWARD_BROWSER_NO_SANDBOX=0.
	sandbox := "--no-sandbox "
	if os.Getenv("RUNEWARD_BROWSER_NO_SANDBOX") == "0" {
		sandbox = ""
	}
	flags := `--headless=new ` + sandbox + `--disable-gpu --disable-dev-shm-usage --hide-scrollbars`
	var fallback string
	if mode == "screenshot" {
		fallback = find + `; "$CHROME" ` + flags + ` ${PROXY:+--proxy-server=$PROXY} --screenshot=/tmp/rw-shot.png ` + shQuote(url) + ` >/dev/null 2>&1; base64 /tmp/rw-shot.png`
	} else {
		fallback = find + `; "$CHROME" ` + flags + ` ${PROXY:+--proxy-server=$PROXY} --dump-dom ` + shQuote(url)
	}
	return `PROXY="${HTTPS_PROXY:-$HTTP_PROXY}"; ` +
		`if command -v runeward-browser >/dev/null 2>&1; then ` + rbCmd + `; else ` + fallback + `; fi`
}

// shQuote single-quotes s for safe interpolation into an `sh -c` script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func resolveFileToolPath(workdir, rel string) (string, error) {
	if strings.TrimSpace(workdir) == "" {
		return rel, nil
	}
	if filepath.IsAbs(rel) {
		return "", badInputError("path %q must be relative to workspace", rel)
	}
	root, err := filepath.Abs(workdir)
	if err != nil {
		root = filepath.Clean(workdir)
	}
	cleaned := filepath.Clean(filepath.Join(root, rel))
	if cleaned != root && !strings.HasPrefix(cleaned, root+string(os.PathSeparator)) {
		return "", badInputError("path %q escapes workspace root", rel)
	}
	return cleaned, nil
}
