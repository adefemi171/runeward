package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	p := writeFile(t, `{
		"principals": [
			{"name": "root", "token": "tok-admin", "admin": true},
			{"name": "reviewer", "token": "tok-rev", "can_approve": true, "allowed_profiles": ["team-*"]},
			{"name": "dev", "token": "tok-dev", "allowed_profiles": ["build", "test-*"]}
		]
	}`)
	s, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3", got)
	}
	if _, ok := s.Identify("tok-admin"); !ok {
		t.Fatalf("expected to identify admin token")
	}
}

func TestLoadDuplicateToken(t *testing.T) {
	p := writeFile(t, `{
		"principals": [
			{"name": "a", "token": "dup"},
			{"name": "b", "token": "dup"}
		]
	}`)
	if _, err := Load(p); err == nil {
		t.Fatalf("expected duplicate-token error, got nil")
	}
}

func TestLoadEmptyToken(t *testing.T) {
	p := writeFile(t, `{"principals": [{"name": "a", "token": ""}]}`)
	if _, err := Load(p); err == nil {
		t.Fatalf("expected empty-token error, got nil")
	}
}

func TestLoadEmptyName(t *testing.T) {
	p := writeFile(t, `{"principals": [{"name": "  ", "token": "t"}]}`)
	if _, err := Load(p); err == nil {
		t.Fatalf("expected empty-name error, got nil")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoadBadJSON(t *testing.T) {
	p := writeFile(t, `{"principals": [`)
	if _, err := Load(p); err == nil {
		t.Fatalf("expected parse error for bad JSON")
	}
}

func TestLoadUnknownField(t *testing.T) {
	p := writeFile(t, `{"principals": [{"name": "a", "token": "t", "bogus": 1}]}`)
	if _, err := Load(p); err == nil {
		t.Fatalf("expected error for unknown field")
	}
}

func TestFromEnvUnset(t *testing.T) {
	t.Setenv(EnvFile, "")
	s, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if s != nil {
		t.Fatalf("expected nil store when env unset, got %v", s)
	}
}

func TestFromEnvSet(t *testing.T) {
	p := writeFile(t, `{"principals": [{"name": "a", "token": "t", "admin": true}]}`)
	t.Setenv(EnvFile, p)
	s, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if s == nil {
		t.Fatalf("expected non-nil store when env set")
	}
	if _, ok := s.Identify("t"); !ok {
		t.Fatalf("expected to identify token from env store")
	}
}

func TestFromEnvSetBadFile(t *testing.T) {
	t.Setenv(EnvFile, filepath.Join(t.TempDir(), "missing.json"))
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected error for missing env file")
	}
}

func TestIdentify(t *testing.T) {
	p := writeFile(t, `{"principals": [{"name": "dev", "token": "secret"}]}`)
	s, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := s.Identify("secret")
	if !ok {
		t.Fatalf("expected hit for known token")
	}
	if got.Name != "dev" {
		t.Fatalf("Name = %q, want dev", got.Name)
	}
	if _, ok := s.Identify("wrong"); ok {
		t.Fatalf("expected miss for unknown token")
	}
	if _, ok := s.Identify(""); ok {
		t.Fatalf("expected miss for empty token")
	}
}

func TestIdentifyDoesNotDependOnByTokenMap(t *testing.T) {
	p := writeFile(t, `{
		"principals": [
			{"name": "dev", "token": "secret-dev"},
			{"name": "ops", "token": "secret-ops"}
		]
	}`)
	s, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s.byToken = nil
	got, ok := s.Identify("secret-ops")
	if !ok {
		t.Fatalf("expected hit after byToken map removal")
	}
	if got.Name != "ops" {
		t.Fatalf("Name = %q, want ops", got.Name)
	}
}

func TestIdentifyNilStore(t *testing.T) {
	var s *Store
	if _, ok := s.Identify("anything"); ok {
		t.Fatalf("expected miss on nil store")
	}
	if s.Len() != 0 {
		t.Fatalf("nil store Len = %d, want 0", s.Len())
	}
}

func TestCanLaunch(t *testing.T) {
	cases := []struct {
		name    string
		p       *Principal
		profile string
		want    bool
	}{
		{"admin bypass", &Principal{Admin: true}, "anything", true},
		{"star all", &Principal{AllowedProfiles: []string{"*"}}, "build", true},
		{"team glob hit", &Principal{AllowedProfiles: []string{"team-*"}}, "team-alpha", true},
		{"team glob miss", &Principal{AllowedProfiles: []string{"team-*"}}, "prod", false},
		{"exact hit", &Principal{AllowedProfiles: []string{"build"}}, "build", true},
		{"exact miss", &Principal{AllowedProfiles: []string{"build"}}, "test", false},
		{"empty list non-admin", &Principal{AllowedProfiles: nil}, "build", false},
		{"multi pattern hit", &Principal{AllowedProfiles: []string{"a", "b-*"}}, "b-1", true},
		{"nil principal", nil, "build", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.CanLaunch(tc.profile); got != tc.want {
				t.Fatalf("CanLaunch(%q) = %v, want %v", tc.profile, got, tc.want)
			}
		})
	}
}

func TestMayApprove(t *testing.T) {
	cases := []struct {
		name string
		p    *Principal
		want bool
	}{
		{"admin", &Principal{Admin: true}, true},
		{"can approve", &Principal{CanApprove: true}, true},
		{"neither", &Principal{}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.MayApprove(); got != tc.want {
				t.Fatalf("MayApprove() = %v, want %v", got, tc.want)
			}
		})
	}
}
