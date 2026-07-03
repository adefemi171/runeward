package policy

import (
	"testing"

	"github.com/adefemi171/runeward/internal/profile"
)

func TestCELEngineEvaluate(t *testing.T) {
	rules := []profile.CELRule{
		{Expr: `tool == "shell" && arg.startsWith("rm ")`, Verdict: profile.VerdictDeny, Reason: "no rm"},
		{Expr: `tool == "file.write" && arg.startsWith("/etc/")`, Verdict: profile.VerdictRequireApprove, Reason: "review /etc"},
		{Expr: `tool == "net" && arg.endsWith(".internal")`, Verdict: profile.VerdictAllow},
	}
	eng, err := NewCEL(rules, profile.VerdictDeny)
	if err != nil {
		t.Fatalf("NewCEL: %v", err)
	}

	cases := []struct {
		tool, arg string
		want      profile.Verdict
	}{
		{"shell", "rm -rf /", profile.VerdictDeny},
		{"shell", "ls -la", profile.VerdictDeny}, // default
		{"file.write", "/etc/motd", profile.VerdictRequireApprove},
		{"file.write", "/workspace/x", profile.VerdictDeny}, // default
		{"net", "db.svc.internal", profile.VerdictAllow},
	}
	for _, tc := range cases {
		got := eng.Evaluate(Action{Tool: tc.tool, Arg: tc.arg})
		if got.Verdict != tc.want {
			t.Errorf("Evaluate(%s,%q) verdict = %q, want %q", tc.tool, tc.arg, got.Verdict, tc.want)
		}
	}
}

func TestCELEngineCompileErrors(t *testing.T) {
	if _, err := NewCEL([]profile.CELRule{{Expr: `arg`}}, ""); err == nil {
		t.Fatal("expected error for non-bool expression")
	}
	if _, err := NewCEL([]profile.CELRule{{Expr: `nope == "x"`}}, ""); err == nil {
		t.Fatal("expected error for unknown variable")
	}
	if _, err := NewCEL([]profile.CELRule{{Expr: ""}}, ""); err == nil {
		t.Fatal("expected error for empty expr")
	}
}

var _ Evaluator = (*CELEngine)(nil)
var _ Evaluator = (*Engine)(nil)
