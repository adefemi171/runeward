// Package browser defines the wire contract between the runeward control
// plane and the in-sandbox browser driver (cmd/runeward-browser), plus a
// minimal Chrome DevTools Protocol client used by the driver. Each driver
// call carries exactly one Command and receives exactly one Result.
package browser

// Command is a single browser action requested over the driver's control
// socket. Exactly one Command is written per connection.
type Command struct {
	// Action selects the operation: navigate|eval|text|html|screenshot|
	// click|type|wait|title|url|close|ping.
	Action    string `json:"action"`
	URL       string `json:"url,omitempty"`
	Selector  string `json:"selector,omitempty"`
	Expr      string `json:"expr,omitempty"`       // JS source for action=eval
	Text      string `json:"text,omitempty"`       // text to type for action=type
	TimeoutMS int    `json:"timeout_ms,omitempty"` // 0 means driver default
}

// Result is the driver's reply to a Command. Exactly one Result is written per
// connection.
type Result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Value is the textual payload (eval result, text, html, title, url).
	Value string `json:"value,omitempty"`
	// Screenshot is a base64 PNG for action=screenshot.
	Screenshot string `json:"screenshot,omitempty"`
}
