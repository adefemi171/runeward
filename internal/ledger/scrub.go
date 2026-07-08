package ledger

import (
	"regexp"
	"strings"
)

// redactMask replaces a detected (but undeclared) secret substring. Declared
// secrets are hashed via redactString instead, so they remain provably linkable
// to a known value; pattern matches are simply masked.
const redactMask = "[REDACTED]"

// secretPatterns matches common credential shapes so a secret pasted into a
// command argument, code snippet, or metadata value is masked in the ledger
// even when it was never declared as an [[env]] secret. Patterns are
// intentionally conservative to avoid mangling ordinary payloads; each match is
// replaced with redactMask (for key/value forms, only the value is replaced).
var secretPatterns = []*regexp.Regexp{
	// PEM private key blocks (any key type).
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
	// JSON Web Tokens.
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}`),
	// Provider-specific tokens.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                 // AWS access key id
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),       // GitHub tokens
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),     // GitHub PATs
	regexp.MustCompile(`xox[a-z]-[A-Za-z0-9-]{10,}`),       // Slack tokens
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),           // Google API key
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{10,}`),       // Anthropic keys
	regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{10,}`),      // OpenAI project keys
	regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`),           // OpenAI-style keys
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{8,}`), // Authorization: Bearer <token>
}

var highEntropyTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

// secretKeyValue masks the value in key=value / key: value pairs whose key names
// a credential (password, token, secret, api_key, access_key, ...). Submatch 1
// is the key-and-separator prefix to keep; submatch 2 is the value to mask.
var secretKeyValue = regexp.MustCompile(
	`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)\s*[=:]\s*)("[^"]+"|'[^']+'|[^\s"'&;]+)`,
)

// Scrubber applies built-in and optional operator-provided scrub patterns.
type Scrubber struct {
	patterns []*regexp.Regexp
}

var defaultScrubber = NewScrubber()

// NewScrubber returns a scrubber that always includes built-in secret patterns.
func NewScrubber(extraPatterns ...*regexp.Regexp) *Scrubber {
	patterns := make([]*regexp.Regexp, 0, len(secretPatterns)+len(extraPatterns))
	patterns = append(patterns, secretPatterns...)
	for _, re := range extraPatterns {
		if re != nil {
			patterns = append(patterns, re)
		}
	}
	return &Scrubber{patterns: patterns}
}

// Scrub returns a copy of ev with secrets removed from its payload fields
// (Action, Args, Meta values). Declared sensitive values are replaced by their
// "sha256:<hex>" digest; additionally, credential-shaped substrings are masked
// with redactMask. Structural fields (Tool, Verdict, SessionID, ...) are always
// preserved. When nothing is changed, ev is returned unmodified (Redacted stays
// false) so clean events remain fully readable. PayloadHash records the hash of
// the original payload so the plaintext can later be proven to match.
func Scrub(ev Event, sensitive ...string) Event {
	return defaultScrubber.Scrub(ev, sensitive...)
}

// Scrub returns a copy of ev with secrets removed from payload fields.
func (sb *Scrubber) Scrub(ev Event, sensitive ...string) Event {
	original := ev
	changed := false

	set := make(map[string]struct{}, len(sensitive))
	for _, secret := range sensitive {
		if secret != "" {
			set[secret] = struct{}{}
		}
	}

	scrub := func(s string) string {
		out := scrubValue(s, set, sb.patterns)
		if out != s {
			changed = true
		}
		return out
	}

	action := scrub(ev.Action)

	var args []string
	if ev.Args != nil {
		args = make([]string, len(ev.Args))
		for i, a := range ev.Args {
			args[i] = scrub(a)
		}
	}

	var meta map[string]string
	if ev.Meta != nil {
		meta = make(map[string]string, len(ev.Meta))
		for k, v := range ev.Meta {
			meta[k] = scrub(v)
		}
	}

	if !changed {
		return original
	}

	ev.Action = action
	ev.Args = args
	ev.Meta = meta
	ev.Redacted = true
	ev.PayloadHash = hashPayload(original)
	return ev
}

// ScrubString masks declared secrets and pattern-detected credentials in a
// free-form string (e.g. tool stdout/stderr) so they aren't returned to
// clients in cleartext. Declared secrets are masked (not hashed) here, since
// the result is meant to stay human-readable.
func ScrubString(s string, sensitive ...string) string {
	return defaultScrubber.ScrubString(s, sensitive...)
}

// ScrubString masks declared secrets and pattern-detected credentials in a
// free-form string.
func (s *Scrubber) ScrubString(in string, sensitive ...string) string {
	if in == "" {
		return ""
	}
	out := in
	for _, secret := range sensitive {
		if secret != "" {
			out = strings.ReplaceAll(out, secret, redactMask)
		}
	}
	out = secretKeyValue.ReplaceAllString(out, "${1}"+redactMask)
	for _, re := range s.patterns {
		out = re.ReplaceAllString(out, redactMask)
	}
	out = highEntropyTokenPattern.ReplaceAllStringFunc(out, maskHighEntropyToken)
	return out
}

// scrubValue applies declared-secret hashing and pattern masking to one string.
func scrubValue(s string, sensitive map[string]struct{}, patterns []*regexp.Regexp) string {
	if s == "" {
		return ""
	}
	// Exact match on a declared secret: hash the whole value.
	if _, ok := sensitive[s]; ok {
		return redactString(s)
	}
	// Declared secret embedded in a larger string: mask the occurrence.
	for secret := range sensitive {
		if secret != "" && s != secret {
			s = strings.ReplaceAll(s, secret, redactMask)
		}
	}
	// Pattern-detected credentials.
	s = secretKeyValue.ReplaceAllString(s, "${1}"+redactMask)
	for _, re := range patterns {
		s = re.ReplaceAllString(s, redactMask)
	}
	s = highEntropyTokenPattern.ReplaceAllStringFunc(s, maskHighEntropyToken)
	return s
}

func maskHighEntropyToken(token string) string {
	if !looksLikeSecretBlob(token) {
		return token
	}
	return redactMask
}

func looksLikeSecretBlob(token string) bool {
	if len(token) < 40 {
		return false
	}
	isHex := true
	var (
		hasLower bool
		hasUpper bool
		hasDigit bool
		hasOther bool
	)
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
			if r > 'f' {
				isHex = false
			}
		case r >= 'A' && r <= 'Z':
			hasUpper = true
			if r > 'F' {
				isHex = false
			}
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '+' || r == '/' || r == '=':
			hasOther = true
			isHex = false
		case r == '-' || r == '_':
			// Separators common in identifiers (container IDs, pod hostnames,
			// UUIDs). They rule out pure hex, but on their own are not a secret
			// signal — otherwise names like "runeward-<hex>" get masked as blobs.
			isHex = false
		default:
			return false
		}
	}

	if isHex {
		if len(token) < 48 {
			return false
		}
		return hasDigit && (hasLower || hasUpper)
	}

	charClasses := 0
	if hasLower {
		charClasses++
	}
	if hasUpper {
		charClasses++
	}
	if hasDigit {
		charClasses++
	}
	if hasOther {
		charClasses++
	}
	if charClasses < 3 {
		return false
	}
	return hasDigit && (hasLower || hasUpper)
}
