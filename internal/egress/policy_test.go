package egress

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyAllowExactMatch(t *testing.T) {
	p := Policy{
		Default: "deny",
		Rules: []Rule{
			{Verdict: "allow", Hostname: "example.com"},
		},
	}
	if !p.Allow("example.com") {
		t.Error("expected exact host example.com to be allowed")
	}
	if !p.Allow("EXAMPLE.COM") {
		t.Error("expected case-insensitive match to be allowed")
	}
	if p.Allow("other.com") {
		t.Error("expected other.com to be denied by default")
	}
}

func TestPolicyAllowWildcard(t *testing.T) {
	p := Policy{
		Default: "deny",
		Rules: []Rule{
			{Verdict: "allow", Hostname: "*.example.com"},
		},
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.example.com", true},
		{"a.b.example.com", true},
		{"evil.com", false},
		{"notexample.com", false},
		{"example.com", false}, // wildcard matches subdomains only
	}
	for _, c := range cases {
		if got := p.Allow(c.host); got != c.want {
			t.Errorf("Allow(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestPolicyDefaultDeny(t *testing.T) {
	p := Policy{Default: "deny"}
	if p.Allow("anything.com") {
		t.Error("default-deny should block unlisted hosts")
	}
}

func TestPolicyDefaultAllow(t *testing.T) {
	p := Policy{Default: "allow"}
	if !p.Allow("anything.com") {
		t.Error("default-allow should permit unlisted hosts")
	}

	// Empty default is treated as allow.
	empty := Policy{}
	if !empty.Allow("anything.com") {
		t.Error("empty default should permit unlisted hosts")
	}
}

func TestPolicyFirstMatchWins(t *testing.T) {
	p := Policy{
		Default: "allow",
		Rules: []Rule{
			{Verdict: "deny", Hostname: "blocked.example.com"},
			{Verdict: "allow", Hostname: "*.example.com"},
		},
	}
	if p.Allow("blocked.example.com") {
		t.Error("first-matching deny rule should override later allow")
	}
	if !p.Allow("ok.example.com") {
		t.Error("later allow rule should still apply to other subdomains")
	}
}

func TestPolicyAllowAddrCIDR(t *testing.T) {
	p := Policy{
		Default: "deny",
		Rules: []Rule{
			{Verdict: "allow", CIDR: "10.0.0.0/8"},
		},
	}
	if !p.AllowAddr("10.1.2.3:443") {
		t.Error("IP inside allowed CIDR should pass")
	}
	if p.AllowAddr("192.168.1.1:443") {
		t.Error("IP outside allowed CIDR should be denied")
	}
}

func TestPolicyAllowAddrHostname(t *testing.T) {
	p := Policy{
		Default: "deny",
		Rules: []Rule{
			{Verdict: "allow", Hostname: "api.example.com"},
		},
	}
	if !p.AllowAddr("api.example.com:443") {
		t.Error("host:port for allowed hostname should pass")
	}
	if p.AllowAddr("evil.com:443") {
		t.Error("host:port for unlisted hostname should be denied")
	}
}

func TestPolicyAllowListedHostname(t *testing.T) {
	p := Policy{
		Default: "allow",
		Rules: []Rule{
			{Verdict: "deny", Hostname: "blocked.example.com"},
			{Verdict: "allow", Hostname: "*.example.com"},
		},
	}
	if p.AllowListedHostname("unknown.test") {
		t.Error("unlisted host should not be implicitly allowlisted")
	}
	if p.AllowListedHostname("blocked.example.com") {
		t.Error("first matching deny should block allowlist match")
	}
	if !p.AllowListedHostname("api.example.com") {
		t.Error("explicit allowlist match should pass")
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := `{"default":"deny","rules":[{"verdict":"allow","hostname":"*.example.com"},{"verdict":"allow","cidr":"10.0.0.0/8"}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.Default != "deny" {
		t.Errorf("Default = %q, want deny", p.Default)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(p.Rules))
	}
	if !p.Allow("api.example.com") {
		t.Error("loaded policy should allow api.example.com")
	}
	if !p.AllowAddr("10.0.0.1:80") {
		t.Error("loaded policy should allow CIDR member")
	}
}

func TestLoadPolicyErrors(t *testing.T) {
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing file")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(bad); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
