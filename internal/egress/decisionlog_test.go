package egress

import (
	"fmt"
	"testing"
)

func TestDecisionLogBoundedPerSandbox(t *testing.T) {
	sandboxID := "decision-test-bounded"
	for i := 0; i < maxDecisionsPerSandbox+7; i++ {
		RecordDecision(sandboxID, "example.com", "1.2.3.4", i%2 == 0, fmt.Sprintf("r-%d", i))
	}
	got := ListDecisions(sandboxID)
	if len(got) != maxDecisionsPerSandbox {
		t.Fatalf("len = %d, want %d", len(got), maxDecisionsPerSandbox)
	}
	if got[0].Reason != "r-7" {
		t.Fatalf("oldest reason = %q, want r-7", got[0].Reason)
	}
	if got[len(got)-1].Reason != fmt.Sprintf("r-%d", maxDecisionsPerSandbox+6) {
		t.Fatalf("newest reason = %q", got[len(got)-1].Reason)
	}
}

func TestSandboxIDFromLoggerPrefix(t *testing.T) {
	if got := sandboxIDFromLoggerPrefix("runeward-egress sb-123 2026/01/01"); got != "sb-123" {
		t.Fatalf("sandbox id = %q, want sb-123", got)
	}
	if got := sandboxIDFromLoggerPrefix("runeward-egress"); got != "" {
		t.Fatalf("sandbox id = %q, want empty", got)
	}
}
