package policy

import (
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
)

func TestMatchArgvCatchesWrappersAndPaths(t *testing.T) {
	rules := []profile.PolicyRule{
		{Tool: "shell", MatchArgv: "rm", Verdict: profile.VerdictDeny, Reason: "no rm"},
	}
	e := New(rules, profile.VerdictAllow)

	deny := []struct {
		name string
		a    Action
	}{
		{"bare rm", Action{Tool: "shell", Arg: "rm -rf /tmp/x", Args: []string{"rm", "-rf", "/tmp/x"}}},
		{"abs path rm", Action{Tool: "shell", Arg: "/bin/rm -rf /tmp/x", Args: []string{"/bin/rm", "-rf", "/tmp/x"}}},
		{"sh -c wrapper", Action{Tool: "shell", Arg: "sh -c 'rm -rf /'", Args: []string{"sh", "-c", "rm -rf /"}}},
		{"bash -c wrapper", Action{Tool: "shell", Args: []string{"/bin/bash", "-c", "rm file"}}},
		{"dash -c wrapper", Action{Tool: "shell", Args: []string{"dash", "-c", "rm file"}}},
		{"ash -c wrapper", Action{Tool: "shell", Args: []string{"ash", "-c", "rm file"}}},
		{"ksh -c wrapper", Action{Tool: "shell", Args: []string{"ksh", "-c", "rm file"}}},
		{"zsh -c wrapper", Action{Tool: "shell", Args: []string{"zsh", "-c", "rm file"}}},
		{"fish -c wrapper", Action{Tool: "shell", Args: []string{"fish", "-c", "rm file"}}},
		{"busybox shell wrapper", Action{Tool: "shell", Args: []string{"busybox", "sh", "-c", "rm file"}}},
		{"env sh wrapper", Action{Tool: "shell", Args: []string{"/usr/bin/env", "sh", "-c", "rm file"}}},
		{"env assignment wrapper", Action{Tool: "shell", Args: []string{"env", "FOO=1", "bash", "-c", "rm file"}}},
		{"env option and dashdash wrapper", Action{Tool: "shell", Args: []string{"env", "-i", "--", "sh", "-c", "rm file"}}},
	}
	for _, tc := range deny {
		if got := e.Evaluate(tc.a); got.Verdict != profile.VerdictDeny {
			t.Errorf("%s: verdict = %s, want deny", tc.name, got.Verdict)
		}
	}

	allow := []struct {
		name string
		a    Action
	}{
		{"different tool exe", Action{Tool: "shell", Args: []string{"remove", "x"}}},
		{"ls", Action{Tool: "shell", Args: []string{"ls", "-la"}}},
		{"echo mentions rm", Action{Tool: "shell", Args: []string{"echo", "rm"}}},
		{"busybox non-shell applet", Action{Tool: "shell", Args: []string{"busybox", "echo", "-c", "rm file"}}},
		{"env with no command", Action{Tool: "shell", Args: []string{"env", "FOO=1"}}},
	}
	for _, tc := range allow {
		if got := e.Evaluate(tc.a); got.Verdict != profile.VerdictAllow {
			t.Errorf("%s: verdict = %s, want allow", tc.name, got.Verdict)
		}
	}
}

func TestMatchArgvFallsBackToArgWhenNoArgv(t *testing.T) {
	e := New([]profile.PolicyRule{
		{Tool: "shell", MatchArgv: "curl", Verdict: profile.VerdictDeny},
	}, profile.VerdictAllow)
	// No Args set; the engine should split Arg into tokens.
	if got := e.Evaluate(Action{Tool: "shell", Arg: "curl http://x"}); got.Verdict != profile.VerdictDeny {
		t.Fatalf("verdict = %s, want deny", got.Verdict)
	}
}
