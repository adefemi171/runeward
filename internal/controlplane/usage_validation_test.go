package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/Runewardd/runeward/internal/accounting"
	"github.com/Runewardd/runeward/internal/profile"
)

func TestRecordUsageRejectsNegative(t *testing.T) {
	m, _ := newTestManager(t, nil, time.Second)
	m.accounting = accounting.New()

	if err := m.RecordUsage("fake-1", -1, 0); err == nil {
		t.Fatal("expected negative tokens to be rejected")
	}
	if err := m.RecordUsage("fake-1", 0, -1); err == nil {
		t.Fatal("expected negative cost to be rejected")
	}
}

func TestRecordUsageIgnoresAbsurdDelta(t *testing.T) {
	m, _ := newTestManager(t, nil, time.Second)
	m.accounting = accounting.New()

	if err := m.RecordUsage("fake-1", maxClientUsageTokenDelta+1, 0); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	u := m.SandboxUsage("fake-1")
	if u.Tokens != 0 || u.CostUSD != 0 {
		t.Fatalf("usage = %+v, want zero usage after ignored delta", u)
	}
}

func TestGovernSkipsBudgetWhenClientUsageIgnored(t *testing.T) {
	t.Setenv("RUNEWARD_IGNORE_CLIENT_USAGE", "1")

	m, _ := newTestManager(t, nil, time.Second)
	m.accounting = accounting.New()
	m.sessions["fake-1"].Profile.Limits = profile.Limits{MaxTokens: 1}

	if err := m.RecordUsage("fake-1", 2, 0); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	res, err := m.Shell(context.Background(), "fake-1", []string{"echo", "ok"}, "")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if res.Verdict != profile.VerdictAllow {
		t.Fatalf("verdict = %q, want %q", res.Verdict, profile.VerdictAllow)
	}
}
