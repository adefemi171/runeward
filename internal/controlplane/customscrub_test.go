package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Runewardd/runeward/internal/ledger"
)

func TestGovernAndRecordUseCustomScrubPatterns(t *testing.T) {
	m, _ := newTestManager(t, nil, time.Second)
	sess := m.sessions["fake-1"]
	sess.scrubber = ledger.NewScrubber(regexp.MustCompile(`RUNETOKEN-[0-9]{4}`))

	res, err := m.Shell(context.Background(), "fake-1", []string{"echo", "RUNETOKEN-4242"}, "")
	if err != nil {
		t.Fatalf("shell: %v", err)
	}
	if strings.Contains(res.Stdout, "RUNETOKEN-4242") {
		t.Fatalf("stdout leaked custom token: %q", res.Stdout)
	}

	events, err := m.Ledger().Records()
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected ledger event to be recorded")
	}
	last := events[len(events)-1]
	if strings.Contains(last.Action, "RUNETOKEN-4242") {
		t.Fatalf("ledger action leaked custom token: %q", last.Action)
	}
	for _, a := range last.Args {
		if strings.Contains(a, "RUNETOKEN-4242") {
			t.Fatalf("ledger args leaked custom token: %v", last.Args)
		}
	}
}

func TestCreateSandboxFailsOnInvalidAuditScrubPattern(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("RUNEWARD_STATE_DIR", t.TempDir())

	const profileBody = `
[host]
type = "container"
image = "alpine:3.20"

[audit]
scrub_patterns = ["("]
`
	if err := os.WriteFile(filepath.Join(configDir, "invalid.toml"), []byte(profileBody), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	m, err := New(configDir)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	_, err = m.CreateSandbox(context.Background(), "invalid", CreateOptions{})
	if err == nil {
		t.Fatal("expected invalid scrub pattern to fail sandbox creation")
	}
	if !strings.Contains(err.Error(), "audit.scrub_patterns") {
		t.Fatalf("error should point to audit.scrub_patterns, got %v", err)
	}
}
