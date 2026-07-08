package policy

import (
	"strings"
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
)

// objectModule returns object-shaped decisions.
const objectModule = `package runeward

default decision := {"verdict": "allow"}

decision := {"verdict": "deny", "reason": "no rm"} if {
	input.tool == "shell"
	startswith(input.arg, "rm ")
}

decision := {"verdict": "require-approval", "reason": "review /etc"} if {
	input.tool == "file.write"
	startswith(input.arg, "/etc/")
}
`

// stringModule returns bare string verdicts.
const stringModule = `package runeward

default decision := "allow"

decision := "deny" if {
	input.tool == "shell"
	startswith(input.arg, "rm ")
}
`

func TestRegoEngineObjectDecisions(t *testing.T) {
	e, err := NewRego(objectModule, "", profile.VerdictAllow)
	if err != nil {
		t.Fatalf("NewRego: %v", err)
	}

	tests := []struct {
		name       string
		action     Action
		wantVerd   profile.Verdict
		wantReason string
	}{
		{"deny rm", Action{Tool: "shell", Arg: "rm -rf /"}, profile.VerdictDeny, "no rm"},
		{"approve etc write", Action{Tool: "file.write", Arg: "/etc/x"}, profile.VerdictRequireApprove, "review /etc"},
		{"default allow", Action{Tool: "shell", Arg: "ls"}, profile.VerdictAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.Evaluate(tt.action)
			if dec.Verdict != tt.wantVerd {
				t.Errorf("verdict = %q, want %q", dec.Verdict, tt.wantVerd)
			}
			if dec.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", dec.Reason, tt.wantReason)
			}
			// A matched decision synthesizes a Rule; the default
			// fallthrough leaves it nil.
			if tt.wantVerd != profile.VerdictAllow || tt.name != "default allow" {
				if dec.Rule == nil {
					t.Errorf("expected synthesized Rule, got nil")
				} else if dec.Rule.Tool != tt.action.Tool || dec.Rule.Match != tt.action.Arg {
					t.Errorf("rule = %+v, want tool=%q match=%q", dec.Rule, tt.action.Tool, tt.action.Arg)
				}
			}
		})
	}
}

func TestRegoEngineStringDecisions(t *testing.T) {
	e, err := NewRego(stringModule, "", profile.VerdictAllow)
	if err != nil {
		t.Fatalf("NewRego: %v", err)
	}

	if dec := e.Evaluate(Action{Tool: "shell", Arg: "rm -rf /"}); dec.Verdict != profile.VerdictDeny {
		t.Errorf("verdict = %q, want deny", dec.Verdict)
	}
	if dec := e.Evaluate(Action{Tool: "shell", Arg: "ls"}); dec.Verdict != profile.VerdictAllow {
		t.Errorf("verdict = %q, want allow", dec.Verdict)
	}
}

func TestRegoEngineInvalidModule(t *testing.T) {
	if _, err := NewRego("package runeward\n\ndecision := {", "", profile.VerdictAllow); err == nil {
		t.Fatal("expected error for invalid module, got nil")
	}
}

func TestRegoEngineDefaultOnUnrecognized(t *testing.T) {
	const mod = `package runeward

default decision := "bogus"
`
	e, err := NewRego(mod, "", profile.VerdictDeny)
	if err != nil {
		t.Fatalf("NewRego: %v", err)
	}
	if dec := e.Evaluate(Action{Tool: "shell", Arg: "ls"}); dec.Verdict != profile.VerdictDeny {
		t.Errorf("verdict = %q, want deny (default)", dec.Verdict)
	}
	if dec := e.Evaluate(Action{Tool: "shell", Arg: "ls"}); dec.Rule != nil {
		t.Errorf("expected nil Rule on default fallback")
	}
}

func TestRegoEngineEvalErrorFailsClosed(t *testing.T) {
	e := &RegoEngine{def: profile.VerdictAllow}
	dec := e.Evaluate(Action{Tool: "shell", Arg: "0"})
	if dec.Verdict != profile.VerdictDeny {
		t.Fatalf("verdict = %q, want deny", dec.Verdict)
	}
	if !strings.Contains(dec.Reason, "rego evaluation") {
		t.Fatalf("reason = %q, want rego evaluation failure context", dec.Reason)
	}
	if dec.Rule == nil {
		t.Fatalf("expected synthesized Rule on fail-closed decision")
	}
}
