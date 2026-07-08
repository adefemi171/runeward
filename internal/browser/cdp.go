package browser

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// defaultCallTimeout bounds how long a CDP call waits for its response.
const defaultCallTimeout = 30 * time.Second

const envAllowPrivateNavigate = "RUNEWARD_BROWSER_ALLOW_PRIVATE_ADDRS"

// Client is a minimal Chrome DevTools Protocol client for a single page-level
// DevTools WebSocket. Calls are matched to responses by id; unsolicited events
// go to one-shot subscribers. A single background read loop demultiplexes the
// socket. Intended for sequential use from one goroutine.
type Client struct {
	conn *websocket.Conn

	// CallTimeout overrides defaultCallTimeout when non-zero.
	CallTimeout time.Duration

	writeMu sync.Mutex // serializes websocket writes (gorilla forbids concurrent writers)

	mu      sync.Mutex
	nextID  int
	pending map[int]chan cdpMessage
	subs    map[string][]chan json.RawMessage
	closed  bool
	err     error

	done chan struct{} // closed when the read loop exits
}

// cdpMessage is the envelope for requests, responses, and events.
type cdpMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cdpError       `json:"error,omitempty"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// evalResponse models the Runtime.evaluate result payload.
type evalResponse struct {
	Result struct {
		Type        string          `json:"type"`
		Subtype     string          `json:"subtype"`
		Value       json.RawMessage `json:"value"`
		Description string          `json:"description"`
	} `json:"result"`
	ExceptionDetails *struct {
		Text      string `json:"text"`
		Exception struct {
			Description string `json:"description"`
		} `json:"exception"`
	} `json:"exceptionDetails"`
}

// Dial connects a Client to a page-level DevTools WebSocket URL.
func Dial(wsURL string) (*Client, error) {
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cdp dial %s: %w", wsURL, err)
	}
	return NewClient(conn), nil
}

// NewClient wraps an already-connected DevTools WebSocket and starts its read
// loop. Exported so tests can supply a fake CDP server.
func NewClient(conn *websocket.Conn) *Client {
	c := &Client{
		conn:    conn,
		nextID:  1,
		pending: make(map[int]chan cdpMessage),
		subs:    make(map[string][]chan json.RawMessage),
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// Close closes the connection, which also stops the read loop.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) callTimeout() time.Duration {
	if c.CallTimeout > 0 {
		return c.CallTimeout
	}
	return defaultCallTimeout
}

// readLoop demultiplexes incoming frames into pending responses (keyed by id)
// and event subscribers (keyed by method).
func (c *Client) readLoop() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.fail(err)
			return
		}
		var msg cdpMessage
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		if msg.Method != "" {
			c.dispatchEvent(msg.Method, msg.Params)
		}
	}
}

// fail records the terminal read error and wakes every blocked caller.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.err = err
		close(c.done)
	}
	c.mu.Unlock()
}

func (c *Client) readErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return fmt.Errorf("cdp connection closed: %w", c.err)
	}
	return fmt.Errorf("cdp connection closed")
}

// call sends a CDP method and blocks for its response (matched by id).
func (c *Client) call(method string, params map[string]any) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, c.readErr()
	}
	id := c.nextID
	c.nextID++
	ch := make(chan cdpMessage, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	env := map[string]any{"id": id, "method": method}
	if params != nil {
		env["params"] = params
	}

	c.writeMu.Lock()
	err := c.conn.WriteJSON(env)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("cdp %s: write: %w", method, err)
	}

	select {
	case msg := <-ch:
		if msg.Error != nil {
			return nil, fmt.Errorf("cdp %s: %s (code %d)", method, msg.Error.Message, msg.Error.Code)
		}
		return msg.Result, nil
	case <-c.done:
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, c.readErr()
	case <-time.After(c.callTimeout()):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("cdp %s: timeout after %s", method, c.callTimeout())
	}
}

// subscribe registers a one-shot listener for the next occurrence of an event
// method. Callers must drain the channel or unsubscribe to avoid a leak.
func (c *Client) subscribe(method string) chan json.RawMessage {
	ch := make(chan json.RawMessage, 1)
	c.mu.Lock()
	c.subs[method] = append(c.subs[method], ch)
	c.mu.Unlock()
	return ch
}

func (c *Client) unsubscribe(method string, ch chan json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	subs := c.subs[method]
	for i, s := range subs {
		if s == ch {
			c.subs[method] = append(subs[:i], subs[i+1:]...)
			return
		}
	}
}

// dispatchEvent delivers an event to its subscribers and clears them
// (one-shot semantics).
func (c *Client) dispatchEvent(method string, params json.RawMessage) {
	c.mu.Lock()
	subs := c.subs[method]
	delete(c.subs, method)
	c.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- params:
		default:
		}
	}
}

// Navigate enables the Page domain, navigates to url, and waits up to timeout
// for Page.loadEventFired. A load-wait timeout is not fatal (the page is often
// still usable), so Navigate returns nil in that case.
func (c *Client) Navigate(url string, timeout time.Duration) error {
	if err := ValidateNavigateURL(url); err != nil {
		return err
	}
	if _, err := c.call("Page.enable", nil); err != nil {
		return err
	}
	// Subscribe before navigating to avoid missing the event.
	loadCh := c.subscribe("Page.loadEventFired")
	defer c.unsubscribe("Page.loadEventFired", loadCh)

	if _, err := c.call("Page.navigate", map[string]any{"url": url}); err != nil {
		return err
	}
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	select {
	case <-loadCh:
	case <-c.done:
		return c.readErr()
	case <-time.After(timeout):
	}
	return nil
}

// ValidateNavigateURL enforces safe browser navigation targets.
func ValidateNavigateURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("navigate: url is required")
	}
	if strings.EqualFold(rawURL, "about:blank") {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("navigate: invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https":
	default:
		return fmt.Errorf("navigate: url scheme %q is not allowed", scheme)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return fmt.Errorf("navigate: url host is required")
	}
	if isPrivateHost(host) && !allowPrivateNavigate() {
		return fmt.Errorf("navigate: target host %q is blocked", host)
	}
	return nil
}

func allowPrivateNavigate() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envAllowPrivateNavigate)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isPrivateHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	// Explicitly keep 169.254.0.0/16 blocked for metadata endpoints.
	if addr.Is4() {
		a4 := addr.As4()
		if a4[0] == 169 && a4[1] == 254 {
			return true
		}
	}
	return false
}

// Eval runs expr via Runtime.evaluate and returns the value as a string.
// Strings come back verbatim; other values as their JSON encoding.
func (c *Client) Eval(expr string) (string, error) {
	raw, err := c.call("Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
		"awaitPromise":  true,
	})
	if err != nil {
		return "", err
	}
	var r evalResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("cdp Runtime.evaluate: decode: %w", err)
	}
	if r.ExceptionDetails != nil {
		msg := r.ExceptionDetails.Exception.Description
		if msg == "" {
			msg = r.ExceptionDetails.Text
		}
		return "", fmt.Errorf("eval exception: %s", msg)
	}
	return stringifyValue(r.Result.Type, r.Result.Value)
}

// stringifyValue renders a Runtime.evaluate value into a string.
func stringifyValue(typ string, value json.RawMessage) (string, error) {
	if typ == "undefined" || len(value) == 0 {
		return "", nil
	}
	if typ == "string" {
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return "", err
		}
		return s, nil
	}
	return string(value), nil
}

// Text returns document.body.innerText (or "" when there is no body).
func (c *Client) Text() (string, error) {
	return c.Eval("document.body ? document.body.innerText : ''")
}

// HTML returns the full serialized document.
func (c *Client) HTML() (string, error) {
	return c.Eval("document.documentElement.outerHTML")
}

// Title returns document.title.
func (c *Client) Title() (string, error) {
	return c.Eval("document.title")
}

// URL returns the current location.href.
func (c *Client) URL() (string, error) {
	return c.Eval("location.href")
}

// Screenshot captures the current viewport as a base64-encoded PNG.
func (c *Client) Screenshot() (string, error) {
	raw, err := c.call("Page.captureScreenshot", map[string]any{"format": "png"})
	if err != nil {
		return "", err
	}
	var r struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("cdp Page.captureScreenshot: decode: %w", err)
	}
	return r.Data, nil
}

// Click finds selector and dispatches a click. Implemented via
// Runtime.evaluate to avoid depending on the DOM/Input CDP domains.
func (c *Client) Click(selector string) error {
	sel, err := jsString(selector)
	if err != nil {
		return err
	}
	expr := "(function(){var el=document.querySelector(" + sel + ");" +
		"if(!el){return false;}el.scrollIntoView({block:'center'});el.click();return true;})()"
	ok, err := c.evalBool(expr)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("click: no element matches %q", selector)
	}
	return nil
}

// Type focuses selector, sets its value, and dispatches input/change events
// so frameworks observe the change.
func (c *Client) Type(selector, text string) error {
	sel, err := jsString(selector)
	if err != nil {
		return err
	}
	val, err := jsString(text)
	if err != nil {
		return err
	}
	expr := "(function(){var el=document.querySelector(" + sel + ");if(!el){return false;}" +
		"el.focus();if('value' in el){el.value=" + val + ";}else{el.textContent=" + val + ";}" +
		"el.dispatchEvent(new Event('input',{bubbles:true}));" +
		"el.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
	ok, err := c.evalBool(expr)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("type: no element matches %q", selector)
	}
	return nil
}

// WaitSelector polls until an element matching selector exists or timeout
// elapses.
func (c *Client) WaitSelector(selector string, timeout time.Duration) error {
	sel, err := jsString(selector)
	if err != nil {
		return err
	}
	expr := "!!document.querySelector(" + sel + ")"
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := c.evalBool(expr)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wait: selector %q not found within %s", selector, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// evalBool evaluates expr and reports whether it produced the boolean true.
func (c *Client) evalBool(expr string) (bool, error) {
	v, err := c.Eval(expr)
	if err != nil {
		return false, err
	}
	return v == "true", nil
}

// jsString encodes s as a JS string literal (via JSON) so it can be safely
// embedded in an eval snippet.
func jsString(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
