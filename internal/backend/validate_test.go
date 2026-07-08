package backend

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
)

func TestValidateSeedDir(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "proj")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	// Unset: anything goes (single-machine default).
	t.Setenv(copyFromRootsEnv, "")
	if err := validateSeedDir(outside); err != nil {
		t.Errorf("with allowlist unset, validateSeedDir(%q) = %v, want nil", outside, err)
	}

	// Set: only paths under a root are allowed.
	t.Setenv(copyFromRootsEnv, root)
	if err := validateSeedDir(inside); err != nil {
		t.Errorf("validateSeedDir(%q) under root = %v, want nil", inside, err)
	}
	if err := validateSeedDir(root); err != nil {
		t.Errorf("validateSeedDir(root) = %v, want nil", err)
	}
	if err := validateSeedDir(outside); err == nil {
		t.Errorf("validateSeedDir(%q) outside roots = nil, want error", outside)
	}
}

func TestValidateFileMode(t *testing.T) {
	for _, ok := range []string{"", "644", "0644", "755", "0000"} {
		if err := validateFileMode(ok); err != nil {
			t.Errorf("validateFileMode(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"644; id", "abc", "9999", "0o644", "8"} {
		if err := validateFileMode(bad); err == nil {
			t.Errorf("validateFileMode(%q) = nil, want error", bad)
		}
	}
}

func TestValidateEnvName(t *testing.T) {
	for _, ok := range []string{"PATH", "_x", "A1_B2", "foo"} {
		if err := validateEnvName(ok); err != nil {
			t.Errorf("validateEnvName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"1ABC", "A B", "A=b", "A;id", ""} {
		if err := validateEnvName(bad); err == nil {
			t.Errorf("validateEnvName(%q) = nil, want error", bad)
		}
	}
}

func TestValidateProjectionPath(t *testing.T) {
	for _, ok := range []string{"a/b", "/root/.config/app", "file.txt", "./x"} {
		if err := validateProjectionPath(ok); err != nil {
			t.Errorf("validateProjectionPath(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc/passwd", "a/../../b", ".."} {
		if err := validateProjectionPath(bad); err == nil {
			t.Errorf("validateProjectionPath(%q) = nil, want error", bad)
		}
	}
}

// makeTar builds a tar with the given (name, linkname) headers; a non-empty
// linkname produces a symlink, otherwise a regular file with body "x".
func makeTar(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		name, link := e[0], e[1]
		if link != "" {
			if err := tw.WriteHeader(&tar.Header{Name: name, Linkname: link, Typeflag: tar.TypeSymlink, Mode: 0o777}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFilterTarSafe(t *testing.T) {
	good := makeTar(t, [][2]string{{"a.txt", ""}, {"sub/b.txt", ""}, {"link", "a.txt"}})
	if err := filterTarSafe(io.Discard, bytes.NewReader(good)); err != nil {
		t.Fatalf("filterTarSafe(good) = %v, want nil", err)
	}

	bad := [][][2]string{
		{{"../escape.txt", ""}},
		{{"/abs.txt", ""}},
		{{"ok.txt", ""}, {"a/../../evil", ""}},
		{{"link", "../../etc/passwd"}},
	}
	for i, entries := range bad {
		data := makeTar(t, entries)
		if err := filterTarSafe(io.Discard, bytes.NewReader(data)); err == nil {
			t.Errorf("case %d: filterTarSafe = nil, want error", i)
		}
	}
}

func TestFilterTarSafeRoundTrips(t *testing.T) {
	src := makeTar(t, [][2]string{{"keep.txt", ""}})
	var out bytes.Buffer
	if err := filterTarSafe(&out, bytes.NewReader(src)); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&out)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "keep.txt" {
		t.Fatalf("name = %q, want keep.txt", hdr.Name)
	}
	body, _ := io.ReadAll(tr)
	if strings.TrimSpace(string(body)) != "x" {
		t.Fatalf("body = %q, want x", body)
	}
}

func TestValidateStrictEgressUser(t *testing.T) {
	tests := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{
			name: "strict egress with exempt uid fails",
			spec: Spec{
				User: "1337",
				Network: profile.Network{
					Default: "deny",
					Enforce: "strict",
				},
			},
			wantErr: true,
		},
		{
			name: "strict egress with exempt uid and gid fails",
			spec: Spec{
				User: "1337:1337",
				Network: profile.Network{
					Default: "deny",
					Enforce: "strict",
				},
			},
			wantErr: true,
		},
		{
			name: "strict egress with different uid passes",
			spec: Spec{
				User: "1000",
				Network: profile.Network{
					Default: "deny",
					Enforce: "strict",
				},
			},
			wantErr: false,
		},
		{
			name: "cooperative egress permits exempt uid",
			spec: Spec{
				User: "1337",
				Network: profile.Network{
					Default: "deny",
					Enforce: "",
				},
			},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStrictEgressUser(tc.spec)
			if tc.wantErr && err == nil {
				t.Fatalf("validateStrictEgressUser() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateStrictEgressUser() = %v, want nil", err)
			}
		})
	}
}
