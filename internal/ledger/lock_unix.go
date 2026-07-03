//go:build !windows

package ledger

import (
	"fmt"
	"os"
	"syscall"
)

// lockFile takes a non-blocking advisory exclusive lock so only one process
// can write a given ledger; a second writer would silently break the chain,
// so we fail fast at startup instead. Released when the file is closed.
func lockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("ledger: %q is already in use by another runeward process (only one writer per ledger; set a distinct $RUNEWARD_STATE_DIR): %w", f.Name(), err)
	}
	return nil
}
