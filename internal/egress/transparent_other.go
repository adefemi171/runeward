//go:build !linux

package egress

import (
	"errors"
	"log"
)

// TransparentProxy is a stub; SO_ORIGINAL_DST interception is Linux-only.
type TransparentProxy struct {
	Policy Policy
	Logger *log.Logger
}

// Serve always fails on non-Linux platforms.
func (t *TransparentProxy) Serve(addr string) error {
	return errors.New("transparent egress proxy is only supported on linux")
}
