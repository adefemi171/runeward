package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSignedProfilesDefaultBehaviorUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.toml"), []byte("host.image = \"img\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := Load("p", Options{ConfigDir: dir})
	if err != nil {
		t.Fatalf("Load() with signature enforcement off = %v, want nil", err)
	}
	if p.Name != "p" {
		t.Fatalf("loaded profile name = %q, want p", p.Name)
	}
}

func TestLoadSignedProfilesRequireKeyEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.toml")
	content := []byte("host.image = \"img\"\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := NewSignature(content, priv)
	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", raw, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(requireSignedProfilesEnv, "1")
	t.Setenv(profileVerifyKeyEnv, "")
	if _, err := Load("p", Options{ConfigDir: dir}); err == nil {
		t.Fatal("Load() without verify key env succeeded with signed-profile enforcement enabled")
	}

	t.Setenv(profileVerifyKeyEnv, base64.StdEncoding.EncodeToString(pub))
	if _, err := Load("p", Options{ConfigDir: dir}); err != nil {
		t.Fatalf("Load() with valid signature enforcement = %v, want nil", err)
	}
}

func TestLoadSignedProfilesRejectsMissingOrInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.toml")
	content := []byte("host.image = \"img\"\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(requireSignedProfilesEnv, "1")
	t.Setenv(profileVerifyKeyEnv, base64.StdEncoding.EncodeToString(pub))

	if _, err := Load("p", Options{ConfigDir: dir}); err == nil {
		t.Fatal("Load() accepted unsigned profile while signature enforcement is enabled")
	}

	if err := os.WriteFile(path+".sig", []byte(`{"format":"runeward.profile.sig.v1","key_id":"abcd","sig":"bogus"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("p", Options{ConfigDir: dir}); err == nil {
		t.Fatal("Load() accepted invalid detached signature")
	}
}

func TestProfileValidateRejectsStrictEgressProxyUID(t *testing.T) {
	p := &Profile{
		Host: Host{
			Type:  HostContainer,
			Image: "img",
			User:  "1337",
		},
		Network: Network{
			Default: "deny",
			Enforce: "strict",
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() accepted strict egress profile with exempt proxy uid")
	}
}
