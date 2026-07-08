// Command runeward-browser is the in-sandbox stateful browser driver, driven
// over CDP.
//
// Usage:
//
//	runeward-browser serve --socket <path> [--proxy <url>]
//	runeward-browser call  --socket <path> [--json '<Command JSON>']
//
// `serve` runs a persistent headless Chromium behind a Unix socket; each
// connection carries one JSON [browser.Command] and one [browser.Result]. The
// page is kept alive across connections, so cookies and storage persist for
// the whole session. `call` sends one Command (from --json or stdin), prints
// the Result, and exits non-zero if Result.OK is false.
package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Runewardd/runeward/internal/browser"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "call":
		runCall(os.Args[2:])
	case "render":
		runRender(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "runeward-browser: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `runeward-browser — in-sandbox CDP browser driver

Usage:
  runeward-browser serve  --socket <path|tcp://addr> [--proxy <url>] [--token <secret>]
  runeward-browser call   --socket <path|tcp://addr> [--token <secret>] [--json '<Command JSON>']
  runeward-browser render [--mode text|screenshot] [--proxy <url>] <url>
`)
}

var chromeNames = []string{
	"chromium",
	"chromium-browser",
	"google-chrome",
	"google-chrome-stable",
	"headless-shell",
}

const (
	envBrowserNoSandbox    = "RUNEWARD_BROWSER_NO_SANDBOX"
	envBrowserControlToken = "RUNEWARD_BROWSER_CONTROL_TOKEN"
)

func findChrome() (string, error) {
	for _, name := range chromeNames {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no chromium binary found (looked for %s)", strings.Join(chromeNames, ", "))
}

// runServe launches Chromium, attaches CDP, and serves the control socket.
func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "", "path to the Unix domain control socket to listen on")
	proxy := fs.String("proxy", "", "HTTP(S) proxy passed to Chromium via --proxy-server")
	token := fs.String("token", "", "shared secret required on control requests (or RUNEWARD_BROWSER_CONTROL_TOKEN)")
	_ = fs.Parse(args)

	if *socket == "" {
		fmt.Fprintln(os.Stderr, "serve: --socket is required")
		os.Exit(2)
	}

	logger := logf("runeward-browser: ")
	if *token == "" {
		*token = strings.TrimSpace(os.Getenv(envBrowserControlToken))
	}

	chrome, err := findChrome()
	if err != nil {
		logger("%v", err)
		os.Exit(1)
	}

	udd, err := os.MkdirTemp("", "runeward-browser-")
	if err != nil {
		logger("create user-data-dir: %v", err)
		os.Exit(1)
	}

	chromeArgs := []string{
		"--headless=new",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		"--remote-debugging-port=0",
		"--user-data-dir=" + udd,
	}
	if browserNoSandboxEnabled() {
		chromeArgs = append(chromeArgs, "--no-sandbox")
	}
	proxyStop := func() {}
	if *proxy != "" {
		localProxy, stop, perr := startProxyAuthForwarder(*proxy, logger)
		if perr != nil {
			// Fall back to the raw URL; unauthenticated proxies still work.
			logger("proxy-auth forwarder: %v (using proxy as-is)", perr)
			localProxy = *proxy
		} else {
			proxyStop = stop
		}
		chromeArgs = append(chromeArgs, "--proxy-server="+localProxy)
	}

	cmd := exec.Command(chrome, chromeArgs...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(udd)
		logger("launch chromium: %v", err)
		os.Exit(1)
	}

	d := &driver{
		chrome:    cmd,
		udd:       udd,
		socket:    *socket,
		token:     *token,
		logger:    logger,
		proxyStop: proxyStop,
	}

	port, err := waitForDevToolsPort(udd, 15*time.Second)
	if err != nil {
		logger("%v", err)
		d.shutdown(1)
	}

	wsURL, err := attachPage(port, 10*time.Second)
	if err != nil {
		logger("attach page: %v", err)
		d.shutdown(1)
	}

	client, err := browser.Dial(wsURL)
	if err != nil {
		logger("cdp dial: %v", err)
		d.shutdown(1)
	}
	d.client = client

	ln, network, err := listenControl(*socket)
	if err != nil {
		logger("listen %s: %v", *socket, err)
		d.shutdown(1)
	}
	if network != "unix" && *token == "" {
		logger("listen %s: --token (or %s) is required for network sockets", *socket, envBrowserControlToken)
		d.shutdown(2)
	}
	d.ln = ln

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger("received %s, shutting down", sig)
		d.shutdown(0)
	}()

	logger("serving on %s (chrome pid %d, devtools port %d)", *socket, cmd.Process.Pid, port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if d.closing() {
				return
			}
			logger("accept: %v", err)
			continue
		}
		d.handleConn(conn)
	}
}

// runRender does a one-shot headless render of a single URL, printing the
// rendered DOM (mode "text") or a base64-encoded PNG (mode "screenshot") to
// stdout. It authenticates to a credentialed proxy exactly like `serve`, so
// governed egress works for one-shot renders too.
func runRender(args []string) {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	mode := fs.String("mode", "text", `"text" (rendered DOM) or "screenshot" (base64 PNG)`)
	proxy := fs.String("proxy", "", "HTTP(S) proxy (embedded credentials are honored)")
	_ = fs.Parse(args)
	target := fs.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "render: a url argument is required")
		os.Exit(2)
	}

	logger := logf("runeward-browser: ")
	chrome, err := findChrome()
	if err != nil {
		logger("%v", err)
		os.Exit(1)
	}
	udd, err := os.MkdirTemp("", "runeward-render-")
	if err != nil {
		logger("create user-data-dir: %v", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(udd) }()

	chromeArgs := []string{
		"--headless=new",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		"--user-data-dir=" + udd,
	}
	if browserNoSandboxEnabled() {
		chromeArgs = append(chromeArgs, "--no-sandbox")
	}
	if *proxy != "" {
		localProxy, stop, perr := startProxyAuthForwarder(*proxy, logger)
		if perr != nil {
			logger("proxy-auth forwarder: %v (using proxy as-is)", perr)
			localProxy = *proxy
		} else {
			defer stop()
		}
		chromeArgs = append(chromeArgs, "--proxy-server="+localProxy)
	}

	if *mode == "screenshot" {
		shotPath := filepath.Join(udd, "shot.png")
		chromeArgs = append(chromeArgs, "--screenshot="+shotPath, target)
		cmd := exec.Command(chrome, chromeArgs...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			logger("chromium: %v", err)
			os.Exit(1)
		}
		data, err := os.ReadFile(shotPath)
		if err != nil {
			logger("read screenshot: %v", err)
			os.Exit(1)
		}
		enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
		_, _ = enc.Write(data)
		_ = enc.Close()
		return
	}

	chromeArgs = append(chromeArgs, "--dump-dom", target)
	cmd := exec.Command(chrome, chromeArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		logger("chromium: %v", err)
		os.Exit(1)
	}
}

// driver holds the long-lived browser session state shared across connections.
type driver struct {
	client    *browser.Client
	chrome    *exec.Cmd
	udd       string
	socket    string
	token     string
	ln        net.Listener
	logger    func(string, ...any)
	proxyStop func()
	execMu    sync.Mutex
	closeOnce sync.Once
	closed    atomicBool
}

func (d *driver) closing() bool { return d.closed.get() }

// shutdown tears everything down once and exits the process with code.
func (d *driver) shutdown(code int) {
	d.closeOnce.Do(func() {
		d.closed.set(true)
		if d.proxyStop != nil {
			d.proxyStop()
		}
		if d.ln != nil {
			_ = d.ln.Close()
		}
		if d.client != nil {
			_ = d.client.Close()
		}
		if d.chrome != nil && d.chrome.Process != nil {
			_ = d.chrome.Process.Kill()
			_, _ = d.chrome.Process.Wait()
		}
		if d.socket != "" {
			_ = os.Remove(d.socket)
		}
		if d.udd != "" {
			_ = os.RemoveAll(d.udd)
		}
	})
	os.Exit(code)
}

// handleConn processes exactly one Command/Result exchange on conn.
func (d *driver) handleConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	var cmd browser.Command
	if err := json.NewDecoder(conn).Decode(&cmd); err != nil {
		writeResult(conn, browser.Result{Error: "decode command: " + err.Error()})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if d.token != "" && subtle.ConstantTimeCompare([]byte(cmd.Token), []byte(d.token)) != 1 {
		writeResult(conn, browser.Result{Error: "unauthorized control token"})
		return
	}

	if cmd.Action == "close" {
		writeResult(conn, browser.Result{OK: true})
		_ = conn.Close()
		d.logger("close requested, shutting down")
		d.shutdown(0)
		return
	}
	writeResult(conn, d.execute(cmd))
}

func (d *driver) execute(cmd browser.Command) browser.Result {
	d.execMu.Lock()
	defer d.execMu.Unlock()

	timeout := time.Duration(cmd.TimeoutMS) * time.Millisecond

	switch cmd.Action {
	case "ping":
		return browser.Result{OK: true}
	case "navigate":
		if cmd.URL == "" {
			return errResult("navigate: url is required")
		}
		if err := browser.ValidateNavigateURL(cmd.URL); err != nil {
			return errResult(err.Error())
		}
		if err := d.client.Navigate(cmd.URL, timeout); err != nil {
			return errResult(err.Error())
		}
		return browser.Result{OK: true}
	case "eval":
		return valueResult(d.client.Eval(cmd.Expr))
	case "text":
		return valueResult(d.client.Text())
	case "html":
		return valueResult(d.client.HTML())
	case "title":
		return valueResult(d.client.Title())
	case "url":
		return valueResult(d.client.URL())
	case "screenshot":
		b64, err := d.client.Screenshot()
		if err != nil {
			return errResult(err.Error())
		}
		return browser.Result{OK: true, Screenshot: b64}
	case "click":
		if cmd.Selector == "" {
			return errResult("click: selector is required")
		}
		if err := d.client.Click(cmd.Selector); err != nil {
			return errResult(err.Error())
		}
		return browser.Result{OK: true}
	case "type":
		if cmd.Selector == "" {
			return errResult("type: selector is required")
		}
		if err := d.client.Type(cmd.Selector, cmd.Text); err != nil {
			return errResult(err.Error())
		}
		return browser.Result{OK: true}
	case "wait":
		if cmd.Selector == "" {
			return errResult("wait: selector is required")
		}
		if err := d.client.WaitSelector(cmd.Selector, timeout); err != nil {
			return errResult(err.Error())
		}
		return browser.Result{OK: true}
	default:
		return errResult("unknown action: " + cmd.Action)
	}
}

func valueResult(v string, err error) browser.Result {
	if err != nil {
		return errResult(err.Error())
	}
	return browser.Result{OK: true, Value: v}
}

func errResult(msg string) browser.Result {
	return browser.Result{OK: false, Error: msg}
}

func writeResult(conn net.Conn, res browser.Result) {
	_ = json.NewEncoder(conn).Encode(res)
}

// browserNoSandboxEnabled reports whether Chromium should launch with
// --no-sandbox. Chromium's own sandbox needs user namespaces, which are
// usually unavailable inside a container, so it is ON by default (matching the
// one-shot render path in internal/controlplane). Under a runtime that provides
// isolation (gVisor/Kata) or userns, operators can keep Chromium's sandbox by
// setting RUNEWARD_BROWSER_NO_SANDBOX=0.
func browserNoSandboxEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envBrowserNoSandbox))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func listenControl(socket string) (net.Listener, string, error) {
	socket = strings.TrimSpace(socket)
	if strings.HasPrefix(socket, "tcp://") {
		addr := strings.TrimPrefix(socket, "tcp://")
		ln, err := net.Listen("tcp", addr)
		return ln, "tcp", err
	}
	if strings.HasPrefix(socket, "unix://") {
		path := strings.TrimPrefix(socket, "unix://")
		_ = os.Remove(path)
		ln, err := net.Listen("unix", path)
		return ln, "unix", err
	}
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	return ln, "unix", err
}

func runCall(args []string) {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	socket := fs.String("socket", "", "path to the driver's Unix domain control socket")
	token := fs.String("token", "", "shared secret for control requests (or RUNEWARD_BROWSER_CONTROL_TOKEN)")
	jsonArg := fs.String("json", "", "Command JSON; if empty, read from stdin")
	_ = fs.Parse(args)

	if *socket == "" {
		fmt.Fprintln(os.Stderr, "call: --socket is required")
		os.Exit(2)
	}

	var raw []byte
	if *jsonArg != "" {
		raw = []byte(*jsonArg)
	} else {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "call: read stdin: %v\n", err)
			os.Exit(2)
		}
		raw = b
	}

	var cmd browser.Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		fmt.Fprintf(os.Stderr, "call: invalid command JSON: %v\n", err)
		os.Exit(2)
	}
	if cmd.Token == "" {
		if *token == "" {
			*token = strings.TrimSpace(os.Getenv(envBrowserControlToken))
		}
		cmd.Token = *token
	}

	conn, err := net.Dial("unix", *socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "call: dial %s: %v\n", *socket, err)
		os.Exit(2)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "call: send command: %v\n", err)
		os.Exit(2)
	}

	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	var res browser.Result
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "call: read result: %v\n", err)
		os.Exit(2)
	}

	out, err := json.Marshal(res)
	if err != nil {
		fmt.Fprintf(os.Stderr, "call: encode result: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
	if !res.OK {
		fmt.Fprintln(os.Stderr, res.Error)
		os.Exit(1)
	}
}

// waitForDevToolsPort polls for the DevToolsActivePort file Chromium writes
// after launch;
func waitForDevToolsPort(udd string, timeout time.Duration) (int, error) {
	path := filepath.Join(udd, "DevToolsActivePort")
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			line := strings.TrimSpace(string(data))
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			}
			if p, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && p > 0 {
				return p, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("DevToolsActivePort not ready within %s", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// target is the slice of a DevTools target descriptor we care about.
type target struct {
	Type                 string `json:"type"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// attachPage returns a page-level DevTools WebSocket URL.
func attachPage(port int, timeout time.Duration) (string, error) {
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		ws, err := newPageWS(base)
		if err == nil && ws != "" {
			return ws, nil
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("no page target available")
			}
			return "", lastErr
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func newPageWS(base string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	for _, method := range []string{http.MethodPut, http.MethodGet} {
		req, err := http.NewRequest(method, base+"/json/new?about:blank", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var t target
			if json.Unmarshal(body, &t) == nil && t.WebSocketDebuggerURL != "" {
				return t.WebSocketDebuggerURL, nil
			}
		}
	}

	resp, err := client.Get(base + "/json")
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var targets []target
	if err := json.Unmarshal(body, &targets); err != nil {
		return "", err
	}
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebuggerURL != "" {
			return t.WebSocketDebuggerURL, nil
		}
	}
	return "", fmt.Errorf("no page target found")
}

func logf(prefix string) func(string, ...any) {
	return func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, prefix+format+"\n", a...)
	}
}

// atomicBool is a mutex-guarded bool for the shutdown flag.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set(v bool) {
	b.mu.Lock()
	b.v = v
	b.mu.Unlock()
}

func (b *atomicBool) get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}
