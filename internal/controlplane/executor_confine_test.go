package controlplane

import "testing"

func TestResolveFileToolPathConfinesToWorkdir(t *testing.T) {
	workdir := t.TempDir()

	got, err := resolveFileToolPath(workdir, "notes/todo.txt")
	if err != nil {
		t.Fatalf("resolveFileToolPath: %v", err)
	}
	if got == "notes/todo.txt" {
		t.Fatalf("expected resolved absolute path, got %q", got)
	}
}

func TestResolveFileToolPathRejectsEscapesAndAbsolute(t *testing.T) {
	workdir := t.TempDir()
	cases := []string{
		"/etc/passwd",
		"../etc/passwd",
		"dir/../../etc/passwd",
	}
	for _, tc := range cases {
		if _, err := resolveFileToolPath(workdir, tc); err == nil {
			t.Fatalf("resolveFileToolPath(%q) expected error", tc)
		}
	}
}
