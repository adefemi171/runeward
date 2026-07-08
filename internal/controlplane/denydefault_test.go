package controlplane

import (
	"testing"

	"github.com/Runewardd/runeward/internal/policy"
	"github.com/Runewardd/runeward/internal/profile"
)

func TestNewEngineNoMatchDefaultsAllow(t *testing.T) {
	p := &profile.Profile{Name: "allow-default"}
	engine, err := newEngine(p)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	dec := engine.Evaluate(policy.Action{Tool: "shell", Arg: "echo hi"})
	if dec.Verdict != profile.VerdictAllow {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, profile.VerdictAllow)
	}
}

func TestNewEngineNoMatchCanDefaultDeny(t *testing.T) {
	p := &profile.Profile{
		Name:          "deny-default",
		PolicyDefault: profile.VerdictDeny,
	}
	engine, err := newEngine(p)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	dec := engine.Evaluate(policy.Action{Tool: "shell", Arg: "echo hi"})
	if dec.Verdict != profile.VerdictDeny {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, profile.VerdictDeny)
	}
}
