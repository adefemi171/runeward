package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/browser"
	"github.com/Runewardd/runeward/internal/profile"
)

// browserDriverBin is the in-sandbox CDP driver (cmd/runeward-browser), shipped
// on PATH in the default sandbox image.
const browserDriverBin = "runeward-browser"

// browserReadyTimeout bounds how long BrowserOpen waits for the driver socket
// to answer a ping.
const browserReadyTimeout = 20 * time.Second

// browserSession tracks one live in-sandbox browser driver.
type browserSession struct {
	id     string
	socket string
	token  string
}

// BrowserOpen starts a stateful CDP browser session in the sandbox and returns
// its id. The driver is launched detached; the egress proxy is threaded through
// via --proxy. Gated by policy as tool "browser" (action "open"), so a deny or
// pending verdict comes back in the ToolResult without starting a session.
func (m *Manager) BrowserOpen(ctx context.Context, id string) (sessionID string, res *ToolResult, err error) {
	sess, err := m.session(id)
	if err != nil {
		return "", nil, err
	}

	sid := randID()
	socket := fmt.Sprintf("/tmp/rw-browser-%s.sock", sid)
	token := randID() + randID()
	// The egress proxy is injected into the *container's* environment by the
	// backend (see proxyEnv), not the control-plane's profile env, so read it at
	// runtime inside the sandbox. runeward-browser stands up a loopback
	// forwarder to satisfy the proxy's Basic auth (Chromium can't).
	start := fmt.Sprintf(
		"command -v %s >/dev/null 2>&1 || { echo 'runeward-browser not found in sandbox image' >&2; exit 127; }; "+
			"PROXY=\"${HTTPS_PROXY:-$HTTP_PROXY}\"; "+
			"setsid %s serve --socket %s --token %s ${PROXY:+--proxy $PROXY} >/tmp/rw-browser-%s.log 2>&1 & echo started",
		browserDriverBin, browserDriverBin, shQuote(socket), shQuote(token), sid,
	)

	res, err = m.govern(ctx, sess, "browser", "open", []string{"open", sid}, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: []string{"sh", "-c", start}, Workdir: sess.Workdir, Env: sess.Env})
	})
	if err != nil {
		return "", nil, err
	}
	if res.Verdict != profile.VerdictAllow {
		return "", res, nil
	}
	if res.ExitCode != 0 {
		return "", nil, fmt.Errorf("start browser driver: %s", strings.TrimSpace(res.Stderr+res.Stdout))
	}

	if err := m.browserWaitReady(ctx, sess, id, socket, token); err != nil {
		return "", nil, err
	}

	sess.browserMu.Lock()
	if sess.browsers == nil {
		sess.browsers = map[string]*browserSession{}
	}
	sess.browsers[sid] = &browserSession{id: sid, socket: socket, token: token}
	sess.browserMu.Unlock()

	return sid, res, nil
}

// BrowserAct sends one action to a live browser session through the governed
// path. Stdout carries the value (or base64 screenshot); a driver-level failure
// surfaces in Reason.
func (m *Manager) BrowserAct(ctx context.Context, id, sessionID string, cmd browser.Command) (*ToolResult, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	bs, err := sess.browser(sessionID)
	if err != nil {
		return nil, err
	}
	if cmd.Action == "" {
		return nil, fmt.Errorf("action is required")
	}

	cmd.Token = bs.token
	payload, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	call := []string{browserDriverBin, "call", "--socket", bs.socket, "--token", bs.token, "--json", string(payload)}

	arg := cmd.Action
	switch {
	case cmd.URL != "":
		arg = cmd.Action + " " + cmd.URL
	case cmd.Selector != "":
		arg = cmd.Action + " " + cmd.Selector
	}

	// A screenshot action returns a base64 PNG in the driver's JSON; skip the
	// text secret-scrubber for stdout so the image isn't masked as a
	// high-entropy blob before we parse it out below.
	rawStdout := cmd.Action == "screenshot"
	res, err := m.governOut(ctx, sess, "browser", arg, call, rawStdout, func(ctx context.Context) (*backend.ExecResult, error) {
		return sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: call, Workdir: sess.Workdir, Env: sess.Env})
	})
	if err != nil {
		return nil, err
	}
	if res.Verdict != profile.VerdictAllow {
		return res, nil
	}

	// `call` exits non-zero on driver failure but still prints Result JSON.
	var out browser.Result
	if e := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &out); e == nil {
		res.Stdout = out.Value
		if out.Screenshot != "" {
			res.Stdout = out.Screenshot
		}
		if !out.OK && out.Error != "" {
			res.Reason = out.Error
		}
	}
	return res, nil
}

// BrowserClose shuts down the driver (best-effort) and always removes local
// bookkeeping.
func (m *Manager) BrowserClose(ctx context.Context, id, sessionID string) error {
	sess, err := m.session(id)
	if err != nil {
		return err
	}
	bs, err := sess.browser(sessionID)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(browser.Command{Action: "close", Token: bs.token})
	_, _ = sess.Backend.Exec(ctx, id, backend.ExecRequest{
		Command: []string{browserDriverBin, "call", "--socket", bs.socket, "--token", bs.token, "--json", string(payload)},
		Workdir: sess.Workdir, Env: sess.Env,
	})
	sess.browserMu.Lock()
	delete(sess.browsers, sessionID)
	sess.browserMu.Unlock()
	m.record(sess, "browser", "close", []string{"close", sessionID}, string(profile.VerdictAllow), 0, 0, "")
	return nil
}

// browserWaitReady pings the driver socket until it answers or the timeout
// elapses.
func (m *Manager) browserWaitReady(ctx context.Context, sess *Session, id, socket, token string) error {
	ping, _ := json.Marshal(browser.Command{Action: "ping", Token: token})
	deadline := time.Now().Add(browserReadyTimeout)
	call := []string{browserDriverBin, "call", "--socket", socket, "--token", token, "--json", string(ping)}
	for {
		res, err := sess.Backend.Exec(ctx, id, backend.ExecRequest{Command: call, Workdir: sess.Workdir, Env: sess.Env})
		if err == nil && res.ExitCode == 0 {
			var out browser.Result
			if json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &out) == nil && out.OK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("browser driver did not become ready within %s", browserReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func (s *Session) browser(sessionID string) (*browserSession, error) {
	s.browserMu.Lock()
	defer s.browserMu.Unlock()
	bs, ok := s.browsers[sessionID]
	if !ok {
		return nil, notFoundError("browser session %q not found", sessionID)
	}
	return bs, nil
}

func randID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
