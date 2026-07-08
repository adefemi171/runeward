// Package authz provides multi-principal, RBAC-style access control for the
// control plane. It generalizes the legacy single static bearer token into a
// set of named principals, each with its own token, an allowed-profile glob
// list, and permission flags.
//
// The zero value and a nil *Store both mean "RBAC not configured", allowing the
// caller to fall back to legacy single-token behavior.
package authz

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
)

// EnvFile is the environment variable that points at the RBAC principals file.
const EnvFile = "RUNEWARD_AUTHZ_FILE"

// Principal is a named identity that authenticates with a bearer token and
// carries its own authorization scope.
type Principal struct {
	// Name is the human-readable identity used as the audit actor.
	Name string `json:"name"`
	// Token is the bearer token that authenticates this principal.
	Token string `json:"token"`
	// AllowedProfiles is a list of glob patterns (path.Match syntax) matched
	// against a profile name. An empty list for a non-admin principal means it
	// may launch nothing; a list containing "*" allows every profile.
	AllowedProfiles []string `json:"allowed_profiles"`
	// CanApprove permits the principal to approve or deny pending actions.
	CanApprove bool `json:"can_approve"`
	// Admin bypasses all profile restrictions and implies approval rights.
	Admin bool `json:"admin"`
}

// CanLaunch reports whether the principal may launch the named profile. Admins
// bypass all restrictions. For non-admins, the profile must match at least one
// of the AllowedProfiles glob patterns.
func (p *Principal) CanLaunch(profile string) bool {
	if p == nil {
		return false
	}
	if p.Admin {
		return true
	}
	for _, pattern := range p.AllowedProfiles {
		if pattern == "*" {
			return true
		}
		if ok, err := path.Match(pattern, profile); err == nil && ok {
			return true
		}
	}
	return false
}

// MayApprove reports whether the principal may approve or deny actions.
func (p *Principal) MayApprove() bool {
	if p == nil {
		return false
	}
	return p.Admin || p.CanApprove
}

// Store holds principals indexed by token. It is safe for concurrent reads.
// A nil *Store means RBAC is not configured.
type Store struct {
	mu         sync.RWMutex
	byToken    map[string]*Principal
	principals []*Principal
	tokenHash  [][32]byte
}

type storeFile struct {
	Principals []*Principal `json:"principals"`
}

// Load reads a JSON principals file of the form:
//
//	{"principals": [ {"name": "...", "token": "...", ...}, ... ]}
//
// It rejects entries with empty names, empty tokens, or duplicate tokens.
func Load(filePath string) (*Store, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("authz: read %s: %w", filePath, err)
	}
	var sf storeFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sf); err != nil {
		return nil, fmt.Errorf("authz: parse %s: %w", filePath, err)
	}
	return newStore(sf.Principals)
}

func newStore(principals []*Principal) (*Store, error) {
	s := &Store{
		byToken:    make(map[string]*Principal, len(principals)),
		principals: make([]*Principal, 0, len(principals)),
		tokenHash:  make([][32]byte, 0, len(principals)),
	}
	for i, p := range principals {
		if p == nil {
			return nil, fmt.Errorf("authz: principal at index %d is null", i)
		}
		if strings.TrimSpace(p.Name) == "" {
			return nil, fmt.Errorf("authz: principal at index %d has empty name", i)
		}
		if p.Token == "" {
			return nil, fmt.Errorf("authz: principal %q has empty token", p.Name)
		}
		if _, dup := s.byToken[p.Token]; dup {
			return nil, fmt.Errorf("authz: duplicate token for principal %q", p.Name)
		}
		s.byToken[p.Token] = p
		s.principals = append(s.principals, p)
		s.tokenHash = append(s.tokenHash, sha256.Sum256([]byte(p.Token)))
	}
	return s, nil
}

// FromEnv builds a Store from the file named by RUNEWARD_AUTHZ_FILE. When the
// variable is unset (or empty) it returns (nil, nil), signaling that RBAC is
// not configured and the caller should fall back to legacy single-token auth.
func FromEnv() (*Store, error) {
	filePath := strings.TrimSpace(os.Getenv(EnvFile))
	if filePath == "" {
		return nil, nil
	}
	return Load(filePath)
}

// Identify returns the principal that owns the given bearer token. It returns
// (nil, false) when the token is unknown, empty, or the store is nil. Token
// comparison is done with a constant-time compare to reduce timing leakage.
func (s *Store) Identify(token string) (*Principal, bool) {
	if s == nil || token == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := sha256.Sum256([]byte(token))
	var match *Principal
	for i, p := range s.principals {
		if subtle.ConstantTimeCompare(s.tokenHash[i][:], h[:]) == 1 {
			match = p
		}
	}
	if match != nil {
		return match, true
	}
	return nil, false
}

// Len reports the number of configured principals. A nil Store has length 0.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.principals)
}

// ErrEmpty is returned by helpers that require a configured store. It is
// exported for callers that wish to distinguish "not configured" from other
// failures.
var ErrEmpty = errors.New("authz: store not configured")
