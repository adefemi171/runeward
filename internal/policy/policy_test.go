package policy

import (
	"testing"

	"github.com/adefemi171/runeward/internal/profile"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		s       string
		want    bool
	}{
		{"empty pattern empty string", "", "", true},
		{"empty pattern nonempty", "", "x", false},
		{"literal match", "rm", "rm", true},
		{"literal mismatch", "rm", "ls", false},
		{"star matches all", "*", "anything at all", true},
		{"star matches empty", "*", "", true},
		{"prefix star", "rm -rf*", "rm -rf /tmp", true},
		{"prefix star no suffix", "rm -rf*", "rm -rf", true},
		{"prefix star mismatch", "rm -rf*", "rmdir /tmp", false},
		{"star crosses slash", "/etc/*", "/etc/passwd", true},
		{"star crosses nested slash", "/etc/*", "/etc/ssh/sshd_config", true},
		{"star mid pattern crosses slash", "/*/passwd", "/etc/passwd", true},
		{"star mid pattern deep slash", "/*/passwd", "/etc/deep/passwd", true},
		{"question single char", "r?", "rm", true},
		{"question requires a char", "r?", "r", false},
		{"question matches slash", "a?b", "a/b", true},
		{"suffix glob", "*.go", "main.go", true},
		{"suffix glob dir", "*.go", "internal/policy/main.go", true},
		{"suffix glob mismatch", "*.go", "main.py", false},
		{"double star greedy", "a*b*c", "axxbyyc", true},
		{"double star backtrack", "a*c", "aXcXc", true},
		{"trailing stars", "abc***", "abc", true},
		{"leading star literal tail", "*passwd", "/etc/passwd", true},
		{"question and star", "?*", "x", true},
		{"question and star empty", "?*", "", false},
		{"exact host", "api.example.com", "api.example.com", true},
		{"wildcard subdomain", "*.example.com", "api.example.com", true},
		{"wildcard subdomain root fails", "*.example.com", "example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchGlob(tt.pattern, tt.s); got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
			}
		})
	}
}

func TestEvaluateAllowDenyApprove(t *testing.T) {
	rules := []profile.PolicyRule{
		{Tool: "shell", Match: "rm -rf*", Verdict: profile.VerdictDeny, Reason: "destructive"},
		{Tool: "net", Match: "*.internal", Verdict: profile.VerdictRequireApprove, Reason: "internal host"},
		{Tool: "file.read", Match: "/etc/*", Verdict: profile.VerdictAllow, Reason: "config read"},
	}
	e := New(rules, profile.VerdictDeny)

	tests := []struct {
		name        string
		action      Action
		wantVerdict profile.Verdict
		wantReason  string
		wantRuleNil bool
	}{
		{
			name:        "deny destructive shell",
			action:      Action{Tool: "shell", Arg: "rm -rf /"},
			wantVerdict: profile.VerdictDeny,
			wantReason:  "destructive",
		},
		{
			name:        "require approval internal net",
			action:      Action{Tool: "net", Arg: "db.internal"},
			wantVerdict: profile.VerdictRequireApprove,
			wantReason:  "internal host",
		},
		{
			name:        "allow etc read",
			action:      Action{Tool: "file.read", Arg: "/etc/hosts"},
			wantVerdict: profile.VerdictAllow,
			wantReason:  "config read",
		},
		{
			name:        "no match falls to default",
			action:      Action{Tool: "python", Arg: "print(1)"},
			wantVerdict: profile.VerdictDeny,
			wantReason:  "",
			wantRuleNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := e.Evaluate(tt.action)
			if d.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", d.Verdict, tt.wantVerdict)
			}
			if d.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", d.Reason, tt.wantReason)
			}
			if tt.wantRuleNil && d.Rule != nil {
				t.Errorf("rule = %+v, want nil", d.Rule)
			}
			if !tt.wantRuleNil && d.Rule == nil {
				t.Errorf("rule = nil, want non-nil")
			}
		})
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	rules := []profile.PolicyRule{
		{Tool: "shell", Match: "git *", Verdict: profile.VerdictAllow, Reason: "first"},
		{Tool: "shell", Match: "git push*", Verdict: profile.VerdictDeny, Reason: "second"},
	}
	e := New(rules, profile.VerdictAllow)

	d := e.Evaluate(Action{Tool: "shell", Arg: "git push origin main"})
	if d.Verdict != profile.VerdictAllow || d.Reason != "first" {
		t.Fatalf("first-match-wins broken: got verdict=%q reason=%q", d.Verdict, d.Reason)
	}
}

func TestEvaluateDefaultWhenEmpty(t *testing.T) {
	e := New(nil, "")
	d := e.Evaluate(Action{Tool: "shell", Arg: "ls"})
	if d.Verdict != profile.VerdictAllow {
		t.Errorf("empty default should be allow, got %q", d.Verdict)
	}
	if d.Rule != nil {
		t.Errorf("expected nil rule for default decision")
	}
}

func TestEvaluateWildcardTool(t *testing.T) {
	rules := []profile.PolicyRule{
		{Tool: "*", Match: "*secret*", Verdict: profile.VerdictDeny, Reason: "secrets"},
	}
	e := New(rules, profile.VerdictAllow)

	for _, tool := range []string{"shell", "file.read", "net", "python"} {
		d := e.Evaluate(Action{Tool: tool, Arg: "cat the-secret-file"})
		if d.Verdict != profile.VerdictDeny {
			t.Errorf("wildcard tool %q: verdict = %q, want deny", tool, d.Verdict)
		}
	}

	d := e.Evaluate(Action{Tool: "shell", Arg: "cat readme"})
	if d.Verdict != profile.VerdictAllow {
		t.Errorf("non-matching arg should fall to default allow, got %q", d.Verdict)
	}
}

func TestEvaluateEmptyMatchMatchesAll(t *testing.T) {
	rules := []profile.PolicyRule{
		{Tool: "net", Match: "", Verdict: profile.VerdictRequireApprove, Reason: "all egress"},
	}
	e := New(rules, profile.VerdictAllow)

	d := e.Evaluate(Action{Tool: "net", Arg: "anything.example.com"})
	if d.Verdict != profile.VerdictRequireApprove {
		t.Errorf("empty match should match all args, got %q", d.Verdict)
	}
	d = e.Evaluate(Action{Tool: "shell", Arg: "ls"})
	if d.Verdict != profile.VerdictAllow {
		t.Errorf("tool mismatch should fall to default, got %q", d.Verdict)
	}
}
