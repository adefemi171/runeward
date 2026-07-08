package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// hasFinding reports whether findings contains an entry with the given
// severity and field.
func hasFinding(findings []Finding, severity, field string) bool {
	for _, f := range findings {
		if f.Severity == severity && f.Field == field {
			return true
		}
	}
	return false
}

func TestLintNil(t *testing.T) {
	if got := Lint(nil); got != nil {
		t.Fatalf("Lint(nil) = %v, want nil", got)
	}
}

func TestLintFindings(t *testing.T) {
	tests := []struct {
		name         string
		profile      *Profile
		wantSeverity string
		wantField    string
	}{
		{
			name:         "missing image warns",
			profile:      &Profile{},
			wantSeverity: SeverityWarn,
			wantField:    "host.image",
		},
		{
			name: "op reference errors",
			profile: &Profile{
				Host: Host{Image: "img"},
				Env:  []EnvVar{{Name: "TOKEN", Op: "op://vault/item/field"}},
			},
			wantSeverity: SeverityError,
			wantField:    "env[0].op",
		},
		{
			name: "env reference warns",
			profile: &Profile{
				Host: Host{Image: "img"},
				Env:  []EnvVar{{Name: "TOKEN", Op: "env://TOKEN"}},
			},
			wantSeverity: SeverityWarn,
			wantField:    "env[0].op",
		},
		{
			name: "duplicate env name errors",
			profile: &Profile{
				Host: Host{Image: "img"},
				Env: []EnvVar{
					{Name: "API", Value: "a"},
					{Name: "API", Value: "b"},
				},
			},
			wantSeverity: SeverityError,
			wantField:    "env[1].name",
		},
		{
			name: "deny default with no allow rules warns",
			profile: &Profile{
				Host:    Host{Image: "img"},
				Network: Network{Default: "deny"},
			},
			wantSeverity: SeverityWarn,
			wantField:    "network.default",
		},
		{
			name: "unreachable hostname rule warns",
			profile: &Profile{
				Host: Host{Image: "img"},
				Network: Network{
					Default: "deny",
					Rules: []NetworkRule{
						{Verdict: "allow", Hostname: "*.example.com"},
						{Verdict: "deny", Hostname: "api.example.com"},
					},
				},
			},
			wantSeverity: SeverityWarn,
			wantField:    "network.rule[1]",
		},
		{
			name: "unreachable cidr rule warns",
			profile: &Profile{
				Host: Host{Image: "img"},
				Network: Network{
					Default: "deny",
					Rules: []NetworkRule{
						{Verdict: "allow", CIDR: "10.0.0.0/8"},
						{Verdict: "deny", CIDR: "10.1.0.0/16"},
					},
				},
			},
			wantSeverity: SeverityWarn,
			wantField:    "network.rule[1]",
		},
		{
			name: "invalid policy verdict errors",
			profile: &Profile{
				Host:   Host{Image: "img"},
				Policy: []PolicyRule{{Tool: "shell", Match: "rm*", Verdict: Verdict("nope")}},
			},
			wantSeverity: SeverityError,
			wantField:    "policy[0]",
		},
		{
			name: "empty policy verdict errors",
			profile: &Profile{
				Host:   Host{Image: "img"},
				Policy: []PolicyRule{{Tool: "shell", Match: "rm*"}},
			},
			wantSeverity: SeverityError,
			wantField:    "policy[0]",
		},
		{
			name: "shadowed policy rule errors on same tool catch-all",
			profile: &Profile{
				Host: Host{Image: "img"},
				Policy: []PolicyRule{
					{Tool: "shell", Match: "*", Verdict: VerdictAllow},
					{Tool: "shell", Match: "rm -rf*", Verdict: VerdictDeny},
				},
			},
			wantSeverity: SeverityError,
			wantField:    "policy[1]",
		},
		{
			name: "shadowed policy rule errors on wildcard tool catch-all",
			profile: &Profile{
				Host: Host{Image: "img"},
				Policy: []PolicyRule{
					{Tool: "*", Verdict: VerdictDeny},
					{Tool: "shell", Match: "ls", Verdict: VerdictAllow},
				},
			},
			wantSeverity: SeverityError,
			wantField:    "policy[1]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := Lint(tc.profile)
			if !hasFinding(findings, tc.wantSeverity, tc.wantField) {
				t.Fatalf("Lint() missing %s finding for %q; got %+v", tc.wantSeverity, tc.wantField, findings)
			}
		})
	}
}

func TestLintEnvFileMissing(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.txt")
	if err := os.WriteFile(present, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.txt")

	p := &Profile{
		Host: Host{Image: "img"},
		Env: []EnvVar{
			{Name: "OK", File: present},
			{Name: "BAD", File: missing},
		},
	}
	findings := Lint(p)
	if hasFinding(findings, SeverityWarn, "env[0].file") {
		t.Fatalf("did not expect a finding for the existing file; got %+v", findings)
	}
	if !hasFinding(findings, SeverityWarn, "env[1].file") {
		t.Fatalf("expected a warn finding for the missing file; got %+v", findings)
	}
}

func TestLintCopyFromMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope")

	p := &Profile{Host: Host{Image: "img", CopyFrom: missing}}
	if !hasFinding(Lint(p), SeverityWarn, "host.copy_from") {
		t.Fatalf("expected warn for missing copy_from path")
	}

	p.Host.CopyFrom = dir // exists
	if hasFinding(Lint(p), SeverityWarn, "host.copy_from") {
		t.Fatalf("did not expect a finding for an existing copy_from path")
	}
}

func TestLintClean(t *testing.T) {
	p := &Profile{
		Host: Host{Image: "img"},
		Env:  []EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}},
		Network: Network{
			Default: "deny",
			Rules: []NetworkRule{
				{Verdict: "allow", Hostname: "api.example.com"},
				{Verdict: "allow", Hostname: "*.internal"},
			},
		},
		Policy: []PolicyRule{
			{Tool: "shell", Match: "rm -rf*", Verdict: VerdictDeny},
			{Tool: "shell", Match: "*", Verdict: VerdictAllow},
		},
	}
	if got := Lint(p); len(got) != 0 {
		t.Fatalf("expected no findings for a clean profile; got %+v", got)
	}
}

func TestLintStableOrder(t *testing.T) {
	p := &Profile{
		Env: []EnvVar{{Name: "X", Op: "op://a/b/c"}},
		Network: Network{
			Default: "deny",
			Rules: []NetworkRule{
				{Verdict: "allow", Hostname: "*.example.com"},
				{Verdict: "deny", Hostname: "a.example.com"},
			},
		},
		Policy: []PolicyRule{{Tool: "shell", Verdict: Verdict("bogus")}},
	}
	first := Lint(p)
	for i := 0; i < 5; i++ {
		got := Lint(p)
		if len(got) != len(first) {
			t.Fatalf("finding count not stable: %d vs %d", len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("finding %d not stable: %+v vs %+v", j, got[j], first[j])
			}
		}
	}
}

func TestLintStrictEgressRejectsExemptUID(t *testing.T) {
	p := &Profile{
		Host: Host{Image: "img", User: "1337"},
		Network: Network{
			Default: "deny",
			Enforce: "strict",
			Rules:   []NetworkRule{{Verdict: "allow", Hostname: "api.example.com"}},
		},
		Policy: []PolicyRule{{Tool: "shell", Match: "*", Verdict: VerdictAllow}},
	}
	if !hasFinding(Lint(p), SeverityError, "host.user") {
		t.Fatalf("expected strict-egress exempt uid lint error on host.user")
	}
}

func TestLintWarnsOnImplicitAllowPolicy(t *testing.T) {
	p := &Profile{
		Host: Host{Image: "img"},
		Network: Network{
			Default: "allow",
		},
	}
	if !hasFinding(Lint(p), SeverityWarn, "policy") {
		t.Fatalf("expected warning for implicit allow-by-default policy")
	}
}

func TestLintWarnsOnRootBroadFileProjection(t *testing.T) {
	p := &Profile{
		Host: Host{Image: "img", User: "root"},
		Files: []File{
			{Path: "/etc/profile"},
		},
		Policy: []PolicyRule{{Tool: "shell", Match: "*", Verdict: VerdictAllow}},
	}
	if !hasFinding(Lint(p), SeverityWarn, "file[0].path") {
		t.Fatalf("expected warning for broad file projection while running as root")
	}
}

func TestLintWarnsOnStrictEgressWithoutAllowRules(t *testing.T) {
	p := &Profile{
		Host: Host{Image: "img"},
		Network: Network{
			Default: "deny",
			Enforce: "strict",
		},
		Policy: []PolicyRule{{Tool: "shell", Match: "*", Verdict: VerdictAllow}},
	}
	if !hasFinding(Lint(p), SeverityWarn, "network.enforce") {
		t.Fatalf("expected warning for strict egress with no allow rules")
	}
}

func TestLintErrorsOnMultiHostHostname(t *testing.T) {
	p := &Profile{
		Host: Host{Image: "img"},
		Network: Network{
			Default: "deny",
			Rules:   []NetworkRule{{Verdict: "allow", Hostname: "example.com, *.github.com"}},
		},
		Policy: []PolicyRule{{Tool: "shell", Match: "*", Verdict: VerdictAllow}},
	}
	if !hasFinding(Lint(p), SeverityError, "network.rule[0].hostname") {
		t.Fatalf("expected error for comma-separated hostname; got %+v", Lint(p))
	}
}

func TestLintWarnsWritableRootfsWithIsolationSettings(t *testing.T) {
	p := &Profile{
		Host: Host{
			Image:    "img",
			ReadOnly: false,
		},
		Network: Network{
			Default: "deny",
			Enforce: "strict",
			Rules:   []NetworkRule{{Verdict: "allow", CIDR: "10.0.0.0/8"}},
		},
		Policy: []PolicyRule{{Tool: "shell", Match: "*", Verdict: VerdictAllow}},
	}
	if !hasFinding(Lint(p), SeverityWarn, "host.read_only") {
		t.Fatalf("expected warning for writable rootfs with strict isolation settings")
	}
}
