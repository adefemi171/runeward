// Package ledger implements an append-only audit ledger stored as JSON Lines.
// Each record embeds the SHA-256 hash of the previous record, so any edit,
// insertion, or reorder breaks the chain and is caught by Verify. Open takes
// an advisory file lock so only one process can write a given ledger at a time.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Event is a single audited action. Callers fill in the descriptive fields;
// Append assigns Seq, Time, PrevHash, and Hash.
type Event struct {
	Seq  int       `json:"seq"`
	Time time.Time `json:"time"`

	SessionID string `json:"session_id"`
	Sandbox   string `json:"sandbox"`
	Profile   string `json:"profile"`
	// Tool is the action surface, e.g. "shell", "file.read", "net", "approval".
	Tool string `json:"tool"`
	// Action is the primary argument: the command, path, or hostname.
	Action  string   `json:"action"`
	Args    []string `json:"args,omitempty"`
	Verdict string   `json:"verdict"`

	ExitCode   int   `json:"exit_code"`
	DurationMS int64 `json:"duration_ms"`

	// Meta keys are sorted before hashing so the record hash is independent
	// of map iteration order.
	Meta map[string]string `json:"meta,omitempty"`

	Redacted bool `json:"redacted"`
	// PayloadHash is the SHA-256 hex of the original payload, recorded when
	// Redacted is true so plaintext can later be proven to match.
	PayloadHash string `json:"payload_hash,omitempty"`

	// PrevHash is empty for the genesis record.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`

	// KeyID and Sig are set when the ledger has a Signer. Both are excluded
	// from hashEvent so signing does not alter the chain hash.
	KeyID string `json:"key_id,omitempty"`
	Sig   string `json:"sig,omitempty"`
}

// Ledger is an append-only, hash-chained audit log backed by a JSON Lines
// file. Construct with Open. Safe for concurrent use.
type Ledger struct {
	mu   sync.Mutex
	f    *os.File
	path string

	// tipHash is the Hash of the most recent record, "" when empty.
	tipHash string
	seq     int

	signer *Signer
}

// SetSigner attaches a Signer so subsequent appends sign each record; nil
// disables signing. Call it after Open, before concurrent appends begin.
func (l *Ledger) SetSigner(s *Signer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.signer = s
}

// Open opens or creates the ledger file at path and recovers the chain tip
// and sequence number so appends continue an existing chain.
func Open(path string) (*Ledger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ledger: open %q: %w", path, err)
	}
	// A second process appending concurrently would interleave sequence
	// numbers and break the chain.
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	l := &Ledger{f: f, path: path}

	recs, err := readAll(path)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if n := len(recs); n > 0 {
		tip := recs[n-1]
		l.tipHash = tip.Hash
		l.seq = tip.Seq
	}
	return l, nil
}

// Close releases the underlying file handle.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Append writes ev as one JSON line with chain fields set, fsyncs, and
// returns the stored event.
func (l *Ledger) Append(ev Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		return Event{}, errors.New("ledger: append on closed ledger")
	}

	ev.Seq = l.seq + 1
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ev.PrevHash = l.tipHash
	ev.Hash = hashEvent(ev)
	if l.signer != nil {
		ev.KeyID = l.signer.KeyID()
		ev.Sig = l.signer.Sign(ev.Hash)
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return Event{}, fmt.Errorf("ledger: marshal seq %d: %w", ev.Seq, err)
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return Event{}, fmt.Errorf("ledger: write seq %d: %w", ev.Seq, err)
	}
	if err := l.f.Sync(); err != nil {
		return Event{}, fmt.Errorf("ledger: sync seq %d: %w", ev.Seq, err)
	}

	l.seq = ev.Seq
	l.tipHash = ev.Hash
	return ev, nil
}

// Records returns every event in the ledger, in write order.
func (l *Ledger) Records() ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return readAll(l.path)
}

// Verify recomputes every record's hash and chain linkage, returning an error
// identifying the first bad record or nil if the chain is intact.
func (l *Ledger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	recs, err := readAll(l.path)
	if err != nil {
		return err
	}

	prev := ""
	for i, ev := range recs {
		if ev.Seq != i+1 {
			return fmt.Errorf("ledger: record %d: out-of-order seq %d (expected %d)", i+1, ev.Seq, i+1)
		}
		if ev.PrevHash != prev {
			return fmt.Errorf("ledger: record seq %d: broken chain, prev_hash %q does not link to previous hash %q", ev.Seq, ev.PrevHash, prev)
		}
		want := hashEvent(ev)
		if ev.Hash != want {
			return fmt.Errorf("ledger: record seq %d: tampered, stored hash %q != recomputed %q", ev.Seq, ev.Hash, want)
		}
		prev = ev.Hash
	}
	return nil
}

// Replay returns the ordered events for a single session.
func (l *Ledger) Replay(sessionID string) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	recs, err := readAll(l.path)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(recs))
	for _, ev := range recs {
		if ev.SessionID == sessionID {
			out = append(out, ev)
		}
	}
	return out, nil
}

// Export writes a pretty-printed JSON array of a session's events to w.
// An empty sessionID exports everything.
func (l *Ledger) Export(w io.Writer, sessionID string) error {
	l.mu.Lock()
	recs, err := readAll(l.path)
	l.mu.Unlock()
	if err != nil {
		return err
	}

	events := recs
	if sessionID != "" {
		events = make([]Event, 0, len(recs))
		for _, ev := range recs {
			if ev.SessionID == sessionID {
				events = append(events, ev)
			}
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(events); err != nil {
		return fmt.Errorf("ledger: export: %w", err)
	}
	return nil
}

// Redact returns a copy of ev with payload fields replaced by their
// "sha256:<hex>" digests and Redacted set. PayloadHash records the hash of
// the original payload so plaintext can later be proven to match without
// touching the ledger. With no sensitive values, the whole payload (Action,
// Args, Meta values) is redacted; otherwise only strings exactly equal to a
// sensitive value are. Structural fields (Tool, Verdict, SessionID) are
// always preserved.
func Redact(ev Event, sensitive ...string) Event {
	ev.PayloadHash = hashPayload(ev)
	ev.Redacted = true

	// Copy slices/maps so we don't mutate the caller's Event.
	if ev.Args != nil {
		args := make([]string, len(ev.Args))
		copy(args, ev.Args)
		ev.Args = args
	}
	if ev.Meta != nil {
		meta := make(map[string]string, len(ev.Meta))
		for k, v := range ev.Meta {
			meta[k] = v
		}
		ev.Meta = meta
	}

	if len(sensitive) == 0 {
		ev.Action = redactString(ev.Action)
		for i, a := range ev.Args {
			ev.Args[i] = redactString(a)
		}
		for k, v := range ev.Meta {
			ev.Meta[k] = redactString(v)
		}
		return ev
	}

	set := make(map[string]struct{}, len(sensitive))
	for _, s := range sensitive {
		set[s] = struct{}{}
	}
	if _, ok := set[ev.Action]; ok {
		ev.Action = redactString(ev.Action)
	}
	for i, a := range ev.Args {
		if _, ok := set[a]; ok {
			ev.Args[i] = redactString(a)
		}
	}
	for k, v := range ev.Meta {
		if _, ok := set[v]; ok {
			ev.Meta[k] = redactString(v)
		}
	}
	return ev
}

// redactString replaces a non-empty string with its "sha256:<hex>" digest.
func redactString(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// hashEvent computes the SHA-256 record hash over the event's core fields
// plus PrevHash, in a fixed order. Each field is length-prefixed so no value
// can imitate another; Meta keys are sorted; Hash, Sig, and KeyID are
// excluded.
func hashEvent(ev Event) string {
	h := sha256.New()
	putInt(h, int64(ev.Seq))
	putStr(h, ev.Time.UTC().Format(time.RFC3339Nano))
	putStr(h, ev.SessionID)
	putStr(h, ev.Sandbox)
	putStr(h, ev.Profile)
	putStr(h, ev.Tool)
	putStr(h, ev.Action)
	putInt(h, int64(len(ev.Args)))
	for _, a := range ev.Args {
		putStr(h, a)
	}
	putStr(h, ev.Verdict)
	putInt(h, int64(ev.ExitCode))
	putInt(h, ev.DurationMS)
	putMeta(h, ev.Meta)
	putBool(h, ev.Redacted)
	putStr(h, ev.PayloadHash)
	putStr(h, ev.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// hashPayload hashes just the payload (Action, Args, sorted Meta) using the
// same encoding as hashEvent.
func hashPayload(ev Event) string {
	h := sha256.New()
	putStr(h, ev.Action)
	putInt(h, int64(len(ev.Args)))
	for _, a := range ev.Args {
		putStr(h, a)
	}
	putMeta(h, ev.Meta)
	return hex.EncodeToString(h.Sum(nil))
}

// putMeta writes entries in sorted-key order so the digest is independent of
// map iteration order.
func putMeta(w io.Writer, m map[string]string) {
	putInt(w, int64(len(m)))
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		putStr(w, k)
		putStr(w, m[k])
	}
}

// putField writes an 8-byte big-endian length prefix followed by b.
func putField(w io.Writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

func putStr(w io.Writer, s string) { putField(w, []byte(s)) }

func putInt(w io.Writer, i int64) { putStr(w, strconv.FormatInt(i, 10)) }

func putBool(w io.Writer, b bool) {
	if b {
		putStr(w, "1")
		return
	}
	putStr(w, "0")
}

// readAll parses every record from path in order. A missing file is an empty
// ledger; blank lines are skipped.
func readAll(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("ledger: read %q: %w", path, err)
	}
	defer f.Close()

	var events []Event
	r := bufio.NewReader(f)
	line := 0
	for {
		line++
		b, readErr := r.ReadBytes('\n')
		trimmed := trimTrailingNewline(b)
		if len(trimmed) > 0 {
			var ev Event
			if err := json.Unmarshal(trimmed, &ev); err != nil {
				return nil, fmt.Errorf("ledger: parse %q line %d: %w", path, line, err)
			}
			events = append(events, ev)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("ledger: read %q line %d: %w", path, line, readErr)
		}
	}
	return events, nil
}

// trimTrailingNewline drops a single trailing "\n" or "\r\n" from b.
func trimTrailingNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n = len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}
