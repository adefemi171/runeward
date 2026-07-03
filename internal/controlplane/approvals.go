package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Approval is a pending human-in-the-loop authorization request. The blocked
// tool call waits on decided until an operator resolves it.
type Approval struct {
	ID      string
	Sandbox string
	Tool    string
	Action  string
	Reason  string
	Created time.Time

	// decided receives true on approve, false on deny. Buffered so a resolver
	// never blocks even if the waiter already timed out.
	decided chan bool
}

// ApprovalView is the JSON projection of an Approval.
type ApprovalView struct {
	ID      string    `json:"id"`
	Sandbox string    `json:"sandbox"`
	Tool    string    `json:"tool"`
	Action  string    `json:"action"`
	Reason  string    `json:"reason"`
	Created time.Time `json:"created"`
}

// ApprovalStore is a concurrency-safe registry of pending approvals.
type ApprovalStore struct {
	mu sync.Mutex
	m  map[string]*Approval
}

// NewApprovalStore returns an empty store.
func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{m: make(map[string]*Approval)}
}

// Create registers a new pending approval and returns it.
func (s *ApprovalStore) Create(sandbox, tool, action, reason string) *Approval {
	ap := &Approval{
		ID:      newID(),
		Sandbox: sandbox,
		Tool:    tool,
		Action:  action,
		Reason:  reason,
		Created: time.Now().UTC(),
		decided: make(chan bool, 1),
	}
	s.mu.Lock()
	s.m[ap.ID] = ap
	s.mu.Unlock()
	return ap
}

// List returns a snapshot of pending approvals in map order; callers sort if
// they need to.
func (s *ApprovalStore) List() []ApprovalView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ApprovalView, 0, len(s.m))
	for _, ap := range s.m {
		out = append(out, ApprovalView{
			ID:      ap.ID,
			Sandbox: ap.Sandbox,
			Tool:    ap.Tool,
			Action:  ap.Action,
			Reason:  ap.Reason,
			Created: ap.Created,
		})
	}
	return out
}

// Resolve delivers a decision to the waiting tool call and removes the
// approval. It reports whether that id was pending.
func (s *ApprovalStore) Resolve(id string, approve bool) bool {
	s.mu.Lock()
	ap, ok := s.m[id]
	if ok {
		delete(s.m, id)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	ap.decided <- approve
	return true
}

// forget drops an approval without delivering a decision, so a timed-out
// waiter doesn't leave an orphaned entry in the inbox.
func (s *ApprovalStore) forget(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
