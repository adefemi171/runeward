package ledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func appendSample(t *testing.T, l *Ledger, session, tool, action string) Event {
	t.Helper()
	ev, err := l.Append(Event{
		SessionID: session,
		Sandbox:   "sbx-1",
		Profile:   "default",
		Tool:      tool,
		Action:    action,
		Verdict:   "allow",
		Meta:      map[string]string{"z": "last", "a": "first"},
	})
	if err != nil {
		t.Fatalf("Append(%s): %v", action, err)
	}
	return ev
}

func TestAppendChainsAndVerifies(t *testing.T) {
	l, _ := newLedger(t)

	e1 := appendSample(t, l, "s1", "shell", "ls -la")
	e2 := appendSample(t, l, "s1", "file.read", "/etc/hosts")
	e3 := appendSample(t, l, "s1", "net", "example.com")

	if e1.Seq != 1 || e2.Seq != 2 || e3.Seq != 3 {
		t.Fatalf("unexpected seqs: %d %d %d", e1.Seq, e2.Seq, e3.Seq)
	}
	if e1.PrevHash != "" {
		t.Fatalf("genesis PrevHash should be empty, got %q", e1.PrevHash)
	}
	if e2.PrevHash != e1.Hash {
		t.Fatalf("e2.PrevHash %q != e1.Hash %q", e2.PrevHash, e1.Hash)
	}
	if e3.PrevHash != e2.Hash {
		t.Fatalf("e3.PrevHash %q != e2.Hash %q", e3.PrevHash, e2.Hash)
	}
	if e1.Time.IsZero() {
		t.Fatal("Append should set Time when zero")
	}

	if err := l.Verify(); err != nil {
		t.Fatalf("Verify on intact chain: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	l, path := newLedger(t)
	appendSample(t, l, "s1", "shell", "echo one")
	appendSample(t, l, "s1", "shell", "echo two")
	appendSample(t, l, "s1", "shell", "echo three")

	if err := l.Verify(); err != nil {
		t.Fatalf("precondition Verify: %v", err)
	}

	// Rewrite the second record's Action on disk, leaving its stored Hash
	// untouched.
	lines := readLines(t, path)
	var ev Event
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ev.Action = "echo TAMPERED"
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lines[1] = string(b)
	writeLines(t, path, lines)

	err = l.Verify()
	if err == nil {
		t.Fatal("expected Verify to fail on tampered record")
	}
	if !strings.Contains(err.Error(), "seq 2") || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("expected error to identify tampered record seq 2, got: %v", err)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l1, err := Open(path)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	a := appendSample(t, l1, "s1", "shell", "first")
	b := appendSample(t, l1, "s1", "shell", "second")
	if err := l1.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer l2.Close()

	c, err := l2.Append(Event{SessionID: "s1", Tool: "shell", Action: "third"})
	if err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}
	if c.Seq != 3 {
		t.Fatalf("expected seq 3 after reopen, got %d", c.Seq)
	}
	if c.PrevHash != b.Hash {
		t.Fatalf("reopened chain PrevHash %q != prior tip %q", c.PrevHash, b.Hash)
	}
	_ = a

	if err := l2.Verify(); err != nil {
		t.Fatalf("Verify after reopen: %v", err)
	}
}

func TestReplayFiltersBySession(t *testing.T) {
	l, _ := newLedger(t)
	appendSample(t, l, "s1", "shell", "a")
	appendSample(t, l, "s2", "shell", "b")
	appendSample(t, l, "s1", "shell", "c")
	appendSample(t, l, "s2", "shell", "d")
	appendSample(t, l, "s1", "shell", "e")

	got, err := l.Replay("s1")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events for s1, got %d", len(got))
	}
	wantActions := []string{"a", "c", "e"}
	for i, ev := range got {
		if ev.SessionID != "s1" {
			t.Fatalf("event %d wrong session %q", i, ev.SessionID)
		}
		if ev.Action != wantActions[i] {
			t.Fatalf("event %d action %q, want %q", i, ev.Action, wantActions[i])
		}
		if i > 0 && got[i-1].Seq >= ev.Seq {
			t.Fatalf("events not in seq order: %d then %d", got[i-1].Seq, ev.Seq)
		}
	}
}

func TestExportProducesValidJSON(t *testing.T) {
	l, _ := newLedger(t)
	appendSample(t, l, "s1", "shell", "a")
	appendSample(t, l, "s2", "shell", "b")
	appendSample(t, l, "s1", "shell", "c")

	var buf bytes.Buffer
	if err := l.Export(&buf, "s1"); err != nil {
		t.Fatalf("Export(s1): %v", err)
	}
	var events []Event
	if err := json.Unmarshal(buf.Bytes(), &events); err != nil {
		t.Fatalf("Export output is not valid JSON array: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 exported events for s1, got %d", len(events))
	}

	buf.Reset()
	if err := l.Export(&buf, ""); err != nil {
		t.Fatalf("Export(all): %v", err)
	}
	events = nil
	if err := json.Unmarshal(buf.Bytes(), &events); err != nil {
		t.Fatalf("Export(all) invalid JSON: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 exported events for all, got %d", len(events))
	}
}

func TestRedactHashesPayloadAndVerifies(t *testing.T) {
	l, _ := newLedger(t)

	raw := Event{
		SessionID: "s1",
		Tool:      "shell",
		Action:    "curl -H 'Authorization: Bearer secret-token' https://api",
		Args:      []string{"secret-token", "keep-me"},
		Meta:      map[string]string{"token": "secret-token", "region": "us"},
	}
	payloadBefore := hashPayload(raw)

	red := Redact(raw, "secret-token")
	if !red.Redacted {
		t.Fatal("Redact should set Redacted=true")
	}
	if red.PayloadHash != payloadBefore {
		t.Fatalf("PayloadHash %q != hash of original payload %q", red.PayloadHash, payloadBefore)
	}
	if red.Args[0] == "secret-token" || !strings.HasPrefix(red.Args[0], "sha256:") {
		t.Fatalf("sensitive arg not redacted: %q", red.Args[0])
	}
	if red.Args[1] != "keep-me" {
		t.Fatalf("non-sensitive arg altered: %q", red.Args[1])
	}
	if red.Meta["token"] == "secret-token" || red.Meta["region"] != "us" {
		t.Fatalf("meta redaction wrong: %+v", red.Meta)
	}
	if raw.Args[0] != "secret-token" || raw.Meta["token"] != "secret-token" {
		t.Fatal("Redact mutated the caller's event")
	}

	stored, err := l.Append(red)
	if err != nil {
		t.Fatalf("Append redacted: %v", err)
	}
	if stored.Hash != hashEvent(stored) {
		t.Fatal("stored redacted event hash mismatch")
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("Verify with redacted event: %v", err)
	}
}

func TestHashIsMapOrderIndependent(t *testing.T) {
	a := Event{Seq: 1, Tool: "shell", Meta: map[string]string{"a": "1", "b": "2", "c": "3"}}
	b := Event{Seq: 1, Tool: "shell", Meta: map[string]string{"c": "3", "b": "2", "a": "1"}}
	if hashEvent(a) != hashEvent(b) {
		t.Fatal("hash must be independent of map insertion order")
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			lines = append(lines, sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return lines
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
