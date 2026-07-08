package controlplane

import (
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
)

func TestNoMatchPolicyVerdictEnvAndProfilePrecedence(t *testing.T) {
	t.Setenv("RUNEWARD_POLICY_DEFAULT", "deny")
	if got := noMatchPolicyVerdict(&profile.Profile{}); got != profile.VerdictDeny {
		t.Fatalf("env deny should set no-match deny, got %q", got)
	}

	if got := noMatchPolicyVerdict(&profile.Profile{PolicyDefault: profile.VerdictAllow}); got != profile.VerdictAllow {
		t.Fatalf("profile allow should override env deny, got %q", got)
	}

	t.Setenv("RUNEWARD_POLICY_DEFAULT", "allow")
	if got := noMatchPolicyVerdict(&profile.Profile{PolicyDefault: profile.VerdictDeny}); got != profile.VerdictDeny {
		t.Fatalf("profile deny should override env allow, got %q", got)
	}
}

func TestNoMatchPolicyVerdictBackCompatAllow(t *testing.T) {
	t.Setenv("RUNEWARD_POLICY_DEFAULT", "")
	if got := noMatchPolicyVerdict(&profile.Profile{}); got != profile.VerdictAllow {
		t.Fatalf("unset profile/env should keep allow default, got %q", got)
	}
}
