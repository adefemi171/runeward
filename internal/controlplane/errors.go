package controlplane

import "fmt"

// ClientError is an error whose message is safe to return to an API caller and
// which maps to a client-facing HTTP status. It lets the server distinguish
// bad input and missing resources (which the caller can act on) from genuine
// internal failures, which must stay opaque so they cannot leak host paths,
// backend detail, or other server-side information.
type ClientError struct {
	// NotFound marks a missing resource (sandbox, fleet, snapshot, browser
	// session) -> 404. When false the error is treated as bad input -> 400.
	NotFound bool
	Message  string
}

func (e *ClientError) Error() string { return e.Message }

// notFoundError reports a missing resource; its message is safe to return.
func notFoundError(format string, args ...any) error {
	return &ClientError{NotFound: true, Message: fmt.Sprintf(format, args...)}
}

// badInputError reports caller-supplied input the control plane rejected; its
// message is safe to return.
func badInputError(format string, args ...any) error {
	return &ClientError{Message: fmt.Sprintf(format, args...)}
}
