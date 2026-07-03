package backend

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// tarball builds an in-memory tar from a list of entries.
func tarball(t *testing.T, hdrs []*tar.Header, bodies []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if bodies[i] != "" {
			if _, err := tw.Write([]byte(bodies[i])); err != nil {
				t.Fatalf("write body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestExtractTarContainsParentTraversal checks that a "../" entry is neutralized
// into destDir rather than escaping it.
func TestExtractTarContainsParentTraversal(t *testing.T) {
	dest := t.TempDir()
	data := tarball(t,
		[]*tar.Header{{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3}},
		[]string{"pwn"},
	)
	if err := extractTar(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); err == nil {
		t.Fatal("traversal wrote a file outside destDir")
	}
	if _, err := os.Stat(filepath.Join(dest, "escape.txt")); err != nil {
		t.Fatalf("traversal entry should have been contained inside destDir: %v", err)
	}
}

// TestExtractTarRejectsSymlinkEscape covers the tar-slip: a symlink pointing
// outside destDir followed by a file written through it must not escape.
func TestExtractTarRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}

	data := tarball(t,
		[]*tar.Header{
			{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777},
			{Name: "link/loot.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4},
		},
		[]string{"", "loot"},
	)
	// Extraction should fail at the unsafe symlink; regardless, nothing may be
	// written into the outside directory.
	_ = extractTar(bytes.NewReader(data), dest)
	if _, err := os.Stat(filepath.Join(outside, "loot.txt")); err == nil {
		t.Fatal("symlink tar-slip wrote a file outside destDir")
	}
}

func TestExtractTarHappyPath(t *testing.T) {
	dest := t.TempDir()
	data := tarball(t,
		[]*tar.Header{
			{Name: "sub/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "sub/a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5},
			{Name: "rel", Typeflag: tar.TypeSymlink, Linkname: "sub/a.txt", Mode: 0o777},
		},
		[]string{"", "hello", ""},
	)
	if err := extractTar(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("happy path failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "sub", "a.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("file not extracted correctly: %q, %v", got, err)
	}
}
