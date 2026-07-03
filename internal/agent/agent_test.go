package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	root := t.TempDir()
	// Resolve symlinks so macOS /var -> /private/var doesn't skew the root.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	srv := New(root)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, root
}

func post(t *testing.T, ts *httptest.Server, path string, body any, out any) int {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response from %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "ok" {
		t.Fatalf("status = %q, want ok", got["status"])
	}
}

func TestFileWriteReadRoundTrip(t *testing.T) {
	ts, root := newTestServer(t)

	var wr fileWriteResponse
	status := post(t, ts, "/v1/file/write", fileWriteRequest{
		Path:    "nested/dir/hello.txt",
		Content: "hello world",
	}, &wr)
	if status != http.StatusOK {
		t.Fatalf("write status = %d, want 200", status)
	}
	if wr.Bytes != len("hello world") {
		t.Fatalf("bytes = %d, want %d", wr.Bytes, len("hello world"))
	}

	if _, err := os.Stat(filepath.Join(root, "nested", "dir", "hello.txt")); err != nil {
		t.Fatalf("nested file not created: %v", err)
	}

	var rd fileReadResponse
	status = post(t, ts, "/v1/file/read", fileReadRequest{Path: "nested/dir/hello.txt"}, &rd)
	if status != http.StatusOK {
		t.Fatalf("read status = %d, want 200", status)
	}
	if rd.Content != "hello world" {
		t.Fatalf("content = %q, want %q", rd.Content, "hello world")
	}
}

func TestFileEditFirstVsAll(t *testing.T) {
	ts, _ := newTestServer(t)

	post(t, ts, "/v1/file/write", fileWriteRequest{Path: "e.txt", Content: "foo foo foo"}, nil)

	var edit fileEditResponse
	status := post(t, ts, "/v1/file/edit", fileEditRequest{Path: "e.txt", Old: "foo", New: "bar"}, &edit)
	if status != http.StatusOK {
		t.Fatalf("edit status = %d, want 200", status)
	}
	if edit.Replacements != 1 {
		t.Fatalf("replacements = %d, want 1", edit.Replacements)
	}
	var rd fileReadResponse
	post(t, ts, "/v1/file/read", fileReadRequest{Path: "e.txt"}, &rd)
	if rd.Content != "bar foo foo" {
		t.Fatalf("content = %q, want %q", rd.Content, "bar foo foo")
	}

	status = post(t, ts, "/v1/file/edit", fileEditRequest{Path: "e.txt", Old: "foo", New: "baz", All: true}, &edit)
	if status != http.StatusOK {
		t.Fatalf("edit-all status = %d, want 200", status)
	}
	if edit.Replacements != 2 {
		t.Fatalf("replacements = %d, want 2", edit.Replacements)
	}
	post(t, ts, "/v1/file/read", fileReadRequest{Path: "e.txt"}, &rd)
	if rd.Content != "bar baz baz" {
		t.Fatalf("content = %q, want %q", rd.Content, "bar baz baz")
	}
}

func TestFileEditMissingOld(t *testing.T) {
	ts, _ := newTestServer(t)
	post(t, ts, "/v1/file/write", fileWriteRequest{Path: "m.txt", Content: "abc"}, nil)

	status := post(t, ts, "/v1/file/edit", fileEditRequest{Path: "m.txt", Old: "zzz", New: "q"}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("edit status = %d, want 400", status)
	}
}

func TestFileList(t *testing.T) {
	ts, _ := newTestServer(t)
	post(t, ts, "/v1/file/write", fileWriteRequest{Path: "a.txt", Content: "x"}, nil)
	post(t, ts, "/v1/file/write", fileWriteRequest{Path: "sub/b.txt", Content: "yy"}, nil)

	var list fileListResponse
	status := post(t, ts, "/v1/file/list", fileListRequest{Path: "."}, &list)
	if status != http.StatusOK {
		t.Fatalf("list status = %d, want 200", status)
	}

	byName := map[string]fileEntry{}
	for _, e := range list.Entries {
		byName[e.Name] = e
	}
	if e, ok := byName["a.txt"]; !ok || e.Dir || e.Size != 1 {
		t.Fatalf("a.txt entry = %+v (ok=%v), want file size 1", e, ok)
	}
	if e, ok := byName["sub"]; !ok || !e.Dir {
		t.Fatalf("sub entry = %+v (ok=%v), want dir", e, ok)
	}
}

func TestFileSearch(t *testing.T) {
	ts, _ := newTestServer(t)
	post(t, ts, "/v1/file/write", fileWriteRequest{Path: "code.go", Content: "package x\n// TODO fix this\nfunc a(){}\n"}, nil)
	post(t, ts, "/v1/file/write", fileWriteRequest{Path: "notes.txt", Content: "TODO ignored by glob\n"}, nil)

	var res fileSearchResponse
	status := post(t, ts, "/v1/file/search", fileSearchRequest{Path: ".", Query: "TODO", Glob: "*.go"}, &res)
	if status != http.StatusOK {
		t.Fatalf("search status = %d, want 200", status)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %d, want 1: %+v", len(res.Matches), res.Matches)
	}
	m := res.Matches[0]
	if m.Path != "code.go" || m.Line != 2 || m.Text != "// TODO fix this" {
		t.Fatalf("match = %+v, want code.go:2 '// TODO fix this'", m)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	ts, _ := newTestServer(t)

	cases := []struct {
		name string
		path string
	}{
		{"dotdot", "../etc/passwd"},
		{"nested-dotdot", "sub/../../etc/passwd"},
		{"absolute", "/etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status := post(t, ts, "/v1/file/read", fileReadRequest{Path: tc.path}, nil); status != http.StatusBadRequest {
				t.Fatalf("read %q status = %d, want 400", tc.path, status)
			}
			if status := post(t, ts, "/v1/file/write", fileWriteRequest{Path: tc.path, Content: "x"}, nil); status != http.StatusBadRequest {
				t.Fatalf("write %q status = %d, want 400", tc.path, status)
			}
		})
	}
}

func TestResolveDirectly(t *testing.T) {
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	s := New(root)

	if _, err := s.resolve("../escape"); err == nil {
		t.Fatal("resolve(../escape) should error")
	}
	if _, err := s.resolve("/abs"); err == nil {
		t.Fatal("resolve(/abs) should error")
	}
	got, err := s.resolve("ok/inside.txt")
	if err != nil {
		t.Fatalf("resolve(ok/inside.txt) unexpected error: %v", err)
	}
	want := filepath.Join(root, "ok", "inside.txt")
	if got != want {
		t.Fatalf("resolve = %q, want %q", got, want)
	}
	if _, err := s.resolve("."); err != nil {
		t.Fatalf("resolve(.) unexpected error: %v", err)
	}
}

func TestShellExec(t *testing.T) {
	ts, _ := newTestServer(t)
	var res execResponse
	status := post(t, ts, "/v1/shell/exec", shellExecRequest{Command: []string{"echo", "hi"}}, &res)
	if status != http.StatusOK {
		t.Fatalf("shell status = %d, want 200", status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit_code = %d, want 0 (stderr=%q)", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "hi\n" {
		t.Fatalf("stdout = %q, want %q", res.Stdout, "hi\n")
	}
}

func TestShellExecEmptyCommand(t *testing.T) {
	ts, _ := newTestServer(t)
	if status := post(t, ts, "/v1/shell/exec", shellExecRequest{Command: nil}, nil); status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

func TestBadJSON(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Post(ts.URL+"/v1/file/read", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
