package policy

import (
	"strings"
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
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

func TestCELEngineRuntimeErrorFailsClosed(t *testing.T) {
	eng, err := NewCEL([]profile.CELRule{
		{Expr: `tool == "shell" && (1 / int(arg)) > 0`, Verdict: profile.VerdictAllow},
	}, profile.VerdictAllow)
	if err != nil {
		t.Fatalf("NewCEL: %v", err)
	}
	dec := eng.Evaluate(Action{Tool: "shell", Arg: "0"})
	if dec.Verdict != profile.VerdictDeny {
		t.Fatalf("verdict = %q, want deny", dec.Verdict)
	}
	if !strings.Contains(dec.Reason, "cel rule 0 evaluation error") {
		t.Fatalf("reason = %q, want cel evaluation error context", dec.Reason)
	}
	if dec.Rule == nil {
		t.Fatalf("expected rule on fail-closed decision")
	}
}

var _ Evaluator = (*CELEngine)(nil)
var _ Evaluator = (*Engine)(nil)
