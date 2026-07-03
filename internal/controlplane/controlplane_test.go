package controlplane

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adefemi171/runeward/internal/backend"
	"github.com/adefemi171/runeward/internal/ledger"
	"github.com/adefemi171/runeward/internal/policy"
	"github.com/adefemi171/runeward/internal/profile"
)

// fakeBackend echoes commands so tests can run without a container runtime.
type fakeBackend struct {
	execs int
}

func (f *fakeBackend) Name() string { return "fake" }

func (f *fakeBackend) Create(ctx context.Context, spec backend.Spec) (*backend.Sandbox, error) {
	return &backend.Sandbox{ID: "fake-1", Profile: spec.Profile, Backend: "fake", Status: "running"}, nil
}

func (f *fakeBackend) Exec(ctx context.Context, id string, req backend.ExecRequest) (*backend.ExecResult, error) {
	f.execs++
	if len(req.Command) > 0 && req.Command[0] == "false" {
		return &backend.ExecResult{ExitCode: 1, Stderr: "failed", Duration: time.Millisecond}, nil
	}
	return &backend.ExecResult{ExitCode: 0, Stdout: strings.Join(req.Command, " "), Duration: time.Millisecond}, nil
}

func (f *fakeBackend) AttachPTY(ctx context.Context, id string, io backend.PTYStream) error {
	return nil
}
func (f *fakeBackend) CopyFiles(ctx context.Context, id string, files []profile.File) error {
	return nil
}
func (f *fakeBackend) ExportWorkspace(ctx context.Context, id string, w io.Writer) error {
	return nil
}
func (f *fakeBackend) Snapshot(ctx context.Context, id, name string) (*backend.SnapshotRef, error) {
	return &backend.SnapshotRef{}, nil
}
func (f *fakeBackend) Restore(ctx context.Context, ref backend.SnapshotRef) (*backend.Sandbox, error) {
	return &backend.Sandbox{}, nil
}
func (f *fakeBackend) Kill(ctx context.Context, id string) error           { return nil }
func (f *fakeBackend) List(ctx context.Context) ([]backend.Sandbox, error) { return nil, nil }

func newTestManager(t *testing.T, rules []profile.PolicyRule, wait time.Duration) (*Manager, *fakeBackend) {
	t.Helper()
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	fb := &fakeBackend{}
	p := &profile.Profile{Name: "test"}
	guard, _ := policy.NewGuard(p.Limits)
	guard.Start()

	m := &Manager{
		ledger:       l,
		approvals:    NewApprovalStore(),
		approvalWait: wait,
		sessions: map[string]*Session{
			"fake-1": {
				Sandbox: &backend.Sandbox{ID: "fake-1", Profile: "test", Backend: "fake", Status: "running"},
				Backend: fb,
				Profile: p,
				Engine:  policy.New(rules, profile.VerdictAllow),
				Guard:   guard,
			},
		},
	}
	return m, fb
}

func TestGovernAllow(t *testing.T) {
	m, _ := newTestManager(t, nil, time.Second)
	res, err := m.Shell(context.Background(), "fake-1", []string{"echo", "hi"}, "")
	if err != nil {
		t.Fatalf("shell: %v", err)
	}
	if res.Verdict != profile.VerdictAllow {
		t.Fatalf("verdict = %q, want allow", res.Verdict)
	}
	if res.Stdout != "echo hi" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if err := m.Ledger().Verify(); err != nil {
		t.Fatalf("ledger verify: %v", err)
	}
}

func TestGovernDeny(t *testing.T) {
	rules := []profile.PolicyRule{{Tool: "shell", Match: "rm *", Verdict: profile.VerdictDeny, Reason: "no deletes"}}
	m, fb := newTestManager(t, rules, time.Second)
	res, err := m.Shell(context.Background(), "fake-1", []string{"rm", "-rf", "/"}, "")
	if err != nil {
		t.Fatalf("shell: %v", err)
	}
	if res.Verdict != profile.VerdictDeny {
		t.Fatalf("verdict = %q, want deny", res.Verdict)
	}
	if fb.execs != 0 {
		t.Fatalf("denied action should not have executed, execs=%d", fb.execs)
	}
	if res.Reason != "no deletes" {
		t.Fatalf("reason = %q", res.Reason)
	}
}

func TestGovernApprovalTimeoutThenPending(t *testing.T) {
	rules := []profile.PolicyRule{{Tool: "file.write", Match: "/etc/*", Verdict: profile.VerdictRequireApprove, Reason: "sensitive path"}}
	m, _ := newTestManager(t, rules, 20*time.Millisecond)
	res, err := m.FileWrite(context.Background(), "fake-1", "/etc/passwd", "x")
	if err != nil {
		t.Fatalf("filewrite: %v", err)
	}
	if res.Verdict != profile.VerdictRequireApprove || !res.Pending {
		t.Fatalf("expected pending require-approval, got %+v", res)
	}
	if res.ApprovalID == "" {
		t.Fatalf("expected approval id")
	}
}

func TestGovernApprovalApproved(t *testing.T) {
	rules := []profile.PolicyRule{{Tool: "file.write", Match: "/etc/*", Verdict: profile.VerdictRequireApprove}}
	m, fb := newTestManager(t, rules, 5*time.Second)

	type outcome struct {
		res *ToolResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := m.FileWrite(context.Background(), "fake-1", "/etc/hosts", "127.0.0.1 x")
		done <- outcome{res, err}
	}()

	// Poll for the approval to appear, then approve it.
	var id string
	for i := 0; i < 100; i++ {
		list := m.Approvals().List()
		if len(list) == 1 {
			id = list[0].ID
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("approval never appeared")
	}
	if !m.Approvals().Resolve(id, true) {
		t.Fatal("resolve failed")
	}

	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("filewrite: %v", o.err)
		}
		if o.res.Verdict != profile.VerdictAllow {
			t.Fatalf("verdict = %q, want allow", o.res.Verdict)
		}
		if fb.execs != 1 {
			t.Fatalf("approved action should have executed once, execs=%d", fb.execs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("filewrite did not complete after approval")
	}
}

func TestGuardMaxExecs(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	p := &profile.Profile{Name: "capped", Limits: profile.Limits{MaxExecs: 1}}
	guard, _ := policy.NewGuard(p.Limits)
	guard.Start()
	m := &Manager{
		ledger:    l,
		approvals: NewApprovalStore(),
		sessions: map[string]*Session{
			"fake-1": {
				Sandbox: &backend.Sandbox{ID: "fake-1", Profile: "capped", Status: "running"},
				Backend: &fakeBackend{},
				Profile: p,
				Engine:  policy.New(nil, profile.VerdictAllow),
				Guard:   guard,
			},
		},
	}

	if res, _ := m.Shell(context.Background(), "fake-1", []string{"echo", "1"}, ""); res.Verdict != profile.VerdictAllow {
		t.Fatalf("first exec verdict = %q", res.Verdict)
	}
	res, _ := m.Shell(context.Background(), "fake-1", []string{"echo", "2"}, "")
	if res.Verdict != profile.VerdictDeny {
		t.Fatalf("second exec should be blocked by max_execs, got %q", res.Verdict)
	}
}
