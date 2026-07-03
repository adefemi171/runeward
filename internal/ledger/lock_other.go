//go:build windows

package ledger

import "os"

// lockFile is a no-op here; the single-writer guarantee is only enforced on
// unix.
func lockFile(_ *os.File) error { return nil }
