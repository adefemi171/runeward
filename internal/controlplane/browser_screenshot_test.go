package controlplane

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Runewardd/runeward/internal/backend"
)

// TestGovernOutRawStdoutPreservesBinary ensures a browser screenshot's base64
// PNG survives the governed path: the high-entropy secret-scrubber would
// otherwise mask the whole blob as "[REDACTED]", returning a broken image.
func TestGovernOutRawStdoutPreservesBinary(t *testing.T) {
	m, _ := newTestManager(t, nil, time.Second)
	sess := m.sessions["fake-1"]

	// A realistic screenshot payload: a long, continuous base64 run (PNG magic
	// prefix), which the high-entropy blob detector masks by default.
	blob := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ" + strings.Repeat("AAAABBBBCCCCDDDD1234", 20)
	run := func(context.Context) (*backend.ExecResult, error) {
		return &backend.ExecResult{ExitCode: 0, Stdout: blob, Duration: time.Millisecond}, nil
	}

	// Default path scrubs stdout: the blob must not survive verbatim.
	scrubbed, err := m.govern(context.Background(), sess, "browser", "u", []string{"u", "text"}, run)
	if err != nil {
		t.Fatalf("govern: %v", err)
	}
	if strings.Contains(scrubbed.Stdout, blob) {
		t.Fatal("expected high-entropy blob to be scrubbed on the default path")
	}

	// rawStdout path leaves the base64 image intact.
	raw, err := m.governOut(context.Background(), sess, "browser", "u", []string{"u", "screenshot"}, true, run)
	if err != nil {
		t.Fatalf("governOut: %v", err)
	}
	if raw.Stdout != blob {
		t.Fatalf("expected screenshot base64 to survive intact, got %q", raw.Stdout)
	}
}
