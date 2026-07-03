package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// On-disk names for the signing key (private, 0600) and its public half
// (0644), stored alongside the ledger.
const (
	keyFileName = "ledger.key"
	pubFileName = "ledger.pub"
)

// Signer signs ledger record hashes with an ed25519 key so a third party
// holding the public key can verify records were not altered.
type Signer struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// LoadOrCreateSigner loads the signing key from dir, generating and
// persisting a new keypair on first use.
func LoadOrCreateSigner(dir string) (*Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ledger: signer dir: %w", err)
	}
	keyPath := filepath.Join(dir, keyFileName)

	if b, err := os.ReadFile(keyPath); err == nil {
		if len(b) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ledger: signing key %q has wrong size %d", keyPath, len(b))
		}
		priv := ed25519.PrivateKey(b)
		return newSigner(priv), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ledger: read signing key: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ledger: generate signing key: %w", err)
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return nil, fmt.Errorf("ledger: write signing key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, pubFileName), []byte(encodePub(pub)+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("ledger: write public key: %w", err)
	}
	return newSigner(priv), nil
}

func newSigner(priv ed25519.PrivateKey) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{priv: priv, pub: pub, keyID: keyID(pub)}
}

// Sign returns the base64 ed25519 signature over a record hash.
func (s *Signer) Sign(hashHex string) string {
	sig := ed25519.Sign(s.priv, []byte(hashHex))
	return base64.StdEncoding.EncodeToString(sig)
}

// Public returns the signer's public key.
func (s *Signer) Public() ed25519.PublicKey { return s.pub }

// KeyID returns the short public-key fingerprint recorded on signed events.
func (s *Signer) KeyID() string { return s.keyID }

// keyID is the first 8 bytes of SHA-256(pub), hex-encoded.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// encodePub returns the base64 encoding of a public key.
func encodePub(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// decodePub parses a base64-encoded ed25519 public key.
func decodePub(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ledger: decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ledger: public key wrong size %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// VerifySignatures recomputes every record's hash and checks signatures
// against pub. When requireAll is true, an unsigned record is an error.
func (l *Ledger) VerifySignatures(pub ed25519.PublicKey, requireAll bool) error {
	l.mu.Lock()
	recs, err := readAll(l.path)
	l.mu.Unlock()
	if err != nil {
		return err
	}
	return verifyRecords(recs, pub, requireAll)
}

func verifyRecords(recs []Event, pub ed25519.PublicKey, requireAll bool) error {
	prev := ""
	for i, ev := range recs {
		if ev.Seq != i+1 {
			return fmt.Errorf("ledger: record %d: out-of-order seq %d (expected %d)", i+1, ev.Seq, i+1)
		}
		if ev.PrevHash != prev {
			return fmt.Errorf("ledger: record seq %d: broken chain", ev.Seq)
		}
		if want := hashEvent(ev); ev.Hash != want {
			return fmt.Errorf("ledger: record seq %d: tampered, hash mismatch", ev.Seq)
		}
		if ev.Sig == "" {
			if requireAll {
				return fmt.Errorf("ledger: record seq %d: missing signature", ev.Seq)
			}
			prev = ev.Hash
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(ev.Sig)
		if err != nil {
			return fmt.Errorf("ledger: record seq %d: bad signature encoding: %w", ev.Seq, err)
		}
		if !ed25519.Verify(pub, []byte(ev.Hash), sig) {
			return fmt.Errorf("ledger: record seq %d: signature does not verify", ev.Seq)
		}
		prev = ev.Hash
	}
	return nil
}

// Bundle is a self-contained export of events plus the public key needed to
// check their signatures, verifiable with VerifyBundle. Trust in the key
// itself is established out of band.
type Bundle struct {
	KeyID     string  `json:"key_id"`
	PublicKey string  `json:"public_key"`
	Events    []Event `json:"events"`
}

// ExportBundle writes a Bundle of the session's events (all events when
// sessionID is ""), embedding pub.
func (l *Ledger) ExportBundle(w io.Writer, sessionID string, pub ed25519.PublicKey) error {
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
	b := Bundle{KeyID: keyID(pub), PublicKey: encodePub(pub), Events: events}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return fmt.Errorf("ledger: export bundle: %w", err)
	}
	return nil
}

// VerifyBundle validates a Bundle read from r: hashes, chain linkage, and a
// signature on every event, checked against the embedded public key. It
// returns the number of verified events. A session bundle need not start at
// seq 1, so linkage is checked between consecutive records only.
func VerifyBundle(r io.Reader) (int, error) {
	var b Bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return 0, fmt.Errorf("ledger: decode bundle: %w", err)
	}
	pub, err := decodePub(b.PublicKey)
	if err != nil {
		return 0, err
	}
	if got := keyID(pub); got != b.KeyID {
		return 0, fmt.Errorf("ledger: bundle key_id %q does not match public key (%q)", b.KeyID, got)
	}
	for i, ev := range b.Events {
		if want := hashEvent(ev); ev.Hash != want {
			return 0, fmt.Errorf("ledger: bundle event %d (seq %d): hash mismatch", i, ev.Seq)
		}
		if i > 0 && ev.PrevHash != b.Events[i-1].Hash {
			return 0, fmt.Errorf("ledger: bundle event %d (seq %d): broken chain", i, ev.Seq)
		}
		if ev.Sig == "" {
			return 0, fmt.Errorf("ledger: bundle event %d (seq %d): missing signature", i, ev.Seq)
		}
		sig, err := base64.StdEncoding.DecodeString(ev.Sig)
		if err != nil {
			return 0, fmt.Errorf("ledger: bundle event %d: bad signature encoding: %w", i, err)
		}
		if !ed25519.Verify(pub, []byte(ev.Hash), sig) {
			return 0, fmt.Errorf("ledger: bundle event %d (seq %d): signature does not verify", i, ev.Seq)
		}
	}
	return len(b.Events), nil
}
