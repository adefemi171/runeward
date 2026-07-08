package ledger

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSignedLedgerVerifiesAndDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	l, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	signer, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	l.SetSigner(signer)

	for i := 0; i < 3; i++ {
		if _, err := l.Append(Event{Tool: "shell", Action: "echo", Verdict: "allow"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	if err := l.VerifySignatures(signer.Public(), true); err != nil {
		t.Fatalf("VerifySignatures should pass: %v", err)
	}

	other, _ := LoadOrCreateSigner(t.TempDir())
	if err := l.VerifySignatures(other.Public(), true); err == nil {
		t.Fatal("verification with wrong key should fail")
	}
}

func TestExportAndVerifyBundle(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(filepath.Join(dir, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	signer, _ := LoadOrCreateSigner(dir)
	l.SetSigner(signer)

	for i := 0; i < 4; i++ {
		if _, err := l.Append(Event{SessionID: "s1", Tool: "shell", Action: "cmd", Verdict: "allow"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	var buf bytes.Buffer
	if err := l.ExportBundle(&buf, "s1", signer.Public()); err != nil {
		t.Fatalf("export bundle: %v", err)
	}

	n, err := VerifyBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if n != 4 {
		t.Fatalf("verified %d events, want 4", n)
	}

	raw := buf.Bytes()
	corrupt := bytes.Replace(raw, []byte("\"cmd\""), []byte("\"xxx\""), 1)
	if _, err := VerifyBundle(bytes.NewReader(corrupt)); err == nil {
		t.Fatal("VerifyBundle should fail on tampered payload")
	}
}

func TestVerifySignaturesRequiresAllWhenKeyProvided(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	l, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := l.Append(Event{Tool: "shell", Action: "echo", Verdict: "allow"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	signer, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if err := l.VerifySignatures(signer.Public(), false); err == nil {
		t.Fatal("expected missing signature failure when verifier key is provided")
	}
}

func TestVerifySignaturesAllowsUnsignedWithoutKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	l, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := l.Append(Event{Tool: "shell", Action: "echo", Verdict: "allow"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	if err := l.VerifySignatures(nil, false); err != nil {
		t.Fatalf("unsigned ledger should verify without key: %v", err)
	}
}
