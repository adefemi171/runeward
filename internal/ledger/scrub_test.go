package ledger

import (
	"regexp"
	"strings"
	"testing"
)

func TestScrubString(t *testing.T) {
	// Declared secret is masked, not left in cleartext.
	if got := ScrubString("token=hunter2 ok", "hunter2"); strings.Contains(got, "hunter2") {
		t.Fatalf("declared secret not masked: %q", got)
	}
	// Undeclared credential-shaped strings are masked by pattern.
	ghToken := "ghp_" + strings.Repeat("a", 36)
	if got := ScrubString("using "+ghToken, nil...); strings.Contains(got, ghToken) {
		t.Fatalf("github token not masked: %q", got)
	}
	// Clean text is returned unchanged.
	clean := "just some regular output"
	if got := ScrubString(clean); got != clean {
		t.Fatalf("clean text changed: %q", got)
	}
	// Empty stays empty.
	if got := ScrubString(""); got != "" {
		t.Fatalf("empty = %q, want empty", got)
	}
}

func TestScrubDeclaredSecretHashed(t *testing.T) {
	raw := Event{
		Tool:   "shell",
		Action: "deploy",
		Args:   []string{"secret-token", "keep-me"},
		Meta:   map[string]string{"token": "secret-token", "region": "us"},
	}
	payloadBefore := hashPayload(raw)

	got := Scrub(raw, "secret-token")
	if !got.Redacted {
		t.Fatal("Scrub should set Redacted=true when it changes the payload")
	}
	if got.PayloadHash != payloadBefore {
		t.Fatalf("PayloadHash %q != hash of original %q", got.PayloadHash, payloadBefore)
	}
	if !strings.HasPrefix(got.Args[0], "sha256:") {
		t.Fatalf("declared secret arg not hashed: %q", got.Args[0])
	}
	if got.Args[1] != "keep-me" {
		t.Fatalf("non-secret arg altered: %q", got.Args[1])
	}
	if got.Meta["region"] != "us" {
		t.Fatalf("non-secret meta altered: %q", got.Meta["region"])
	}
	if raw.Args[0] != "secret-token" {
		t.Fatal("Scrub mutated the caller's event")
	}
}

func TestScrubUndeclaredSecretPatterns(t *testing.T) {
	cases := map[string]string{
		"aws-access-key-id":     "export AWS_KEY=AKIAIOSFODNN7EXAMPLE",
		"anthropic-key":         "ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdefABCDEF",
		"openai-project-key":    "OPENAI_API_KEY=sk-proj-myproj_0123456789abcdefABCDEF",
		"openai-key":            "OPENAI_API_KEY=sk-0123456789abcdefABCDEF0123456789",
		"aws-secret-access-key": "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"github-ghp":            "token is ghp_0123456789abcdefghijABCDEFGHIJ0123",
		"github-gho":            "token is gho_0123456789abcdefghijABCDEFGHIJ0123",
		"github-ghs":            "token is ghs_0123456789abcdefghijABCDEFGHIJ0123",
		"github-ghr":            "token is ghr_0123456789abcdefghijABCDEFGHIJ0123",
		"github-pat":            "token is github_pat_11ABCDEF_0123456789abcdefghijklmnopqrstuvwxyz",
		"google-api-key":        "GOOGLE_API_KEY=AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
		"slack-token":           "SLACK_BOT_TOKEN=xoxb-123456789012-123456789012-abcDEFghiJKL",
		"bearer":                "curl -H 'Authorization: Bearer abcdef123456.token'",
		"kv":                    "run with password=hunter2super here",
		"high-entropy-base64":   "blob=QWxhZGRpbjpPcGVuU2VzYW1lLzEyMzQ1Njc4OUFCQ0RFRkdISQ==",
		"high-entropy-hex":      "hex=0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for name, action := range cases {
		t.Run(name, func(t *testing.T) {
			got := Scrub(Event{Tool: "shell", Action: action})
			if !got.Redacted {
				t.Fatalf("expected redaction for %q", action)
			}
			if !strings.Contains(got.Action, redactMask) {
				t.Fatalf("expected mask in scrubbed action, got %q", got.Action)
			}
		})
	}
}

func TestScrubStringHighEntropyAvoidsSimpleBlobs(t *testing.T) {
	clean := "hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got := ScrubString(clean); got != clean {
		t.Fatalf("expected clean repetitive token to stay unchanged, got %q", got)
	}
}

// TestScrubStringKeepsIdentifierHostnames guards against masking structured
// identifiers (e.g. a Kubernetes pod hostname "runeward-<hex>"): a word prefix
// plus a hex suffix joined by a separator is not a secret blob.
func TestScrubStringKeepsIdentifierHostnames(t *testing.T) {
	for _, id := range []string{
		"runeward-24daaf633799a22bcc94dfff65674bb4",
		"pod-abc123def456abc123def456abc123def4560000",
	} {
		if got := ScrubString(id); got != id {
			t.Fatalf("identifier %q was masked to %q", id, got)
		}
	}
	// A genuine base64 blob (uses +/=) must still be masked.
	blob := "QWxhZGRpbjpPcGVuU2VzYW1lLzEyMzQ1Njc4OUFCQ0RFRkdISQ=="
	if got := ScrubString(blob); !strings.Contains(got, redactMask) {
		t.Fatalf("expected base64 blob to be masked, got %q", got)
	}
}

func TestScrubLeavesCleanPayloadUntouched(t *testing.T) {
	raw := Event{Tool: "shell", Action: "ls -la", Args: []string{"ls", "-la"}}
	got := Scrub(raw)
	if got.Redacted {
		t.Fatal("clean payload should not be marked redacted")
	}
	if got.Action != "ls -la" || got.PayloadHash != "" {
		t.Fatalf("clean payload altered: %+v", got)
	}
}

func TestScrubKeepsKeyDropsValue(t *testing.T) {
	got := Scrub(Event{Tool: "shell", Action: "DB_PASSWORD=supersecret123"})
	if strings.Contains(got.Action, "supersecret123") {
		t.Fatalf("secret value leaked: %q", got.Action)
	}
	if !strings.Contains(got.Action, "DB_PASSWORD=") {
		t.Fatalf("key should be preserved: %q", got.Action)
	}
}

func TestScrubberAppliesCustomPatterns(t *testing.T) {
	custom := regexp.MustCompile(`RUNETOKEN-[0-9]{4}`)
	s := NewScrubber(custom)

	raw := Event{Tool: "shell", Action: "send RUNETOKEN-4242 now"}
	got := s.Scrub(raw)
	if !got.Redacted {
		t.Fatal("expected custom pattern to redact event payload")
	}
	if strings.Contains(got.Action, "RUNETOKEN-4242") {
		t.Fatalf("custom token leaked in action: %q", got.Action)
	}

	out := s.ScrubString("stdout RUNETOKEN-4242 and ghp_0123456789abcdefghijABCDEFGHIJ0123")
	if strings.Contains(out, "RUNETOKEN-4242") {
		t.Fatalf("custom token leaked in scrubbed string: %q", out)
	}
	if strings.Contains(out, "ghp_0123456789abcdefghijABCDEFGHIJ0123") {
		t.Fatalf("built-in token leaked in scrubbed string: %q", out)
	}
}
