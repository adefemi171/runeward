// Package fleet implements an in-memory task board that workers pull from.
// Every operation runs under a single mutex, so each task is claimed by at
// most one worker at a time. Claims are served FIFO, and failed tasks can be
// requeued for retry.
package fleet

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TaskState is the lifecycle state of a [Task].
type TaskState string

// A task starts pending, becomes claimed when a worker takes it, and finishes
// done or failed. A failed task may be requeued back to pending.
const (
	StatePending TaskState = "pending"
	StateClaimed TaskState = "claimed"
	StateDone    TaskState = "done"
	StateFailed  TaskState = "failed"
)

// Sentinel errors returned by [Board] methods.
var (
	ErrNotFound          = errors.New("fleet: task not found")
	ErrIllegalTransition = errors.New("fleet: illegal state transition")
)

// Task is a unit of work on the board. Board methods hand out copies, so
// callers can never mutate board state through a returned value.
type Task struct {
	ID      string    `json:"id"`
	Payload string    `json:"payload"`
	State   TaskState `json:"state"`
	// Owner is the worker that last claimed the task; cleared on requeue.
	Owner string `json:"owner"`
	// Attempts counts claims, not completions.
	Attempts  int       `json:"attempts"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Result    string    `json:"result"`
	Error     string    `json:"error"`
	// LeaseExpiry is when the current claim expires; Sweep requeues claimed
	// tasks past it. Zero means no lease (claims never expire).
	LeaseExpiry time.Time `json:"lease_expiry,omitempty"`
}

// Stats is a point-in-time count of tasks by state.
type Stats struct {
	Total   int `json:"total"`
	Pending int `json:"pending"`
	Claimed int `json:"claimed"`
	Done    int `json:"done"`
	Failed  int `json:"failed"`
}

// Board is an in-memory task board. Construct with NewBoard or Seed. All
// methods are safe for concurrent use.
type Board struct {
	mu    sync.Mutex
	tasks map[string]*Task
	// order records IDs in insertion order and defines FIFO claim order.
	order []string
	// lease is how long a claim is valid without a heartbeat; 0 disables
	// expiry.
	lease time.Duration
}

// NewBoard returns an empty board ready for use.
func NewBoard() *Board {
	return &Board{tasks: make(map[string]*Task)}
}

// SetLease sets the claim lease duration. When d > 0, Claim stamps a deadline
// of now+d, Heartbeat extends it, and Sweep requeues tasks whose lease has
// passed. Non-positive d disables lease expiry.
func (b *Board) SetLease(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lease = d
}

// Load reconstructs a board from an Export snapshot, preserving IDs, states,
// and insertion order.
func Load(tasks []Task, lease time.Duration) *Board {
	b := &Board{tasks: make(map[string]*Task, len(tasks)), lease: lease}
	for i := range tasks {
		t := tasks[i]
		cp := t
		b.tasks[cp.ID] = &cp
		b.order = append(b.order, cp.ID)
	}
	return b
}

// Export returns a copy of every task in insertion order, suitable for
// serialization.
func (b *Board) Export() []Task {
	return b.List()
}

// Seed returns a new board with one pending task per payload, added in order.
func Seed(payloads []string) *Board {
	b := NewBoard()
	for _, p := range payloads {
		b.Add(p)
	}
	return b
}

// Add enqueues a new pending task with the given payload and returns a copy.
func (b *Board) Add(payload string) *Task {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().UTC()
	t := &Task{
		ID:        newID(),
		Payload:   payload,
		State:     StatePending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	b.tasks[t.ID] = t
	b.order = append(b.order, t.ID)

	cp := *t
	return &cp
}

// Claim takes the oldest pending task, marks it claimed by owner, and returns
// a copy. It returns false if nothing is pending. The scan-and-mutate runs
// under the board mutex, so two callers can never get the same task.
func (b *Board) Claim(owner string) (Task, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, id := range b.order {
		t := b.tasks[id]
		if t.State != StatePending {
			continue
		}
		now := time.Now().UTC()
		t.State = StateClaimed
		t.Owner = owner
		t.Attempts++
		t.UpdatedAt = now
		if b.lease > 0 {
			t.LeaseExpiry = now.Add(b.lease)
		}
		return *t, true
	}
	return Task{}, false
}

// Heartbeat extends the lease on a claimed task held by owner. It fails if
// the task doesn't exist, isn't claimed, or is claimed by someone else.
func (b *Board) Heartbeat(id, owner string) (Task, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	t, ok := b.tasks[id]
	if !ok {
		return Task{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if t.State != StateClaimed {
		return Task{}, fmt.Errorf("%w: heartbeat requires claimed, task %q is %s", ErrIllegalTransition, id, t.State)
	}
	if t.Owner != owner {
		return Task{}, fmt.Errorf("%w: task %q is owned by %q, not %q", ErrIllegalTransition, id, t.Owner, owner)
	}
	now := time.Now().UTC()
	t.UpdatedAt = now
	if b.lease > 0 {
		t.LeaseExpiry = now.Add(b.lease)
	}
	return *t, nil
}

// Sweep requeues every claimed task whose lease expired as of now, so a dead
// worker's task returns to the pending pool. Attempts are retained. It
// returns copies of the requeued tasks; tasks with no lease are never swept.
func (b *Board) Sweep(now time.Time) []Task {
	b.mu.Lock()
	defer b.mu.Unlock()

	var requeued []Task
	for _, id := range b.order {
		t := b.tasks[id]
		if t.State != StateClaimed || t.LeaseExpiry.IsZero() {
			continue
		}
		if now.After(t.LeaseExpiry) {
			t.State = StatePending
			t.Owner = ""
			t.LeaseExpiry = time.Time{}
			t.Error = "lease expired; requeued"
			t.UpdatedAt = now.UTC()
			requeued = append(requeued, *t)
		}
	}
	return requeued
}

// Complete marks the claimed task id as done with the given result.
func (b *Board) Complete(id, result string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	t, ok := b.tasks[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if t.State != StateClaimed {
		return fmt.Errorf("%w: complete requires claimed, task %q is %s", ErrIllegalTransition, id, t.State)
	}
	t.State = StateDone
	t.Result = result
	t.Error = ""
	t.LeaseExpiry = time.Time{}
	t.UpdatedAt = time.Now().UTC()
	return nil
}

// Fail marks the claimed task id as failed with errMsg. When requeue is true
// the task instead goes back to the pending pool (owner cleared, attempts
// kept) so another worker can retry it.
func (b *Board) Fail(id, errMsg string, requeue bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	t, ok := b.tasks[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if t.State != StateClaimed {
		return fmt.Errorf("%w: fail requires claimed, task %q is %s", ErrIllegalTransition, id, t.State)
	}
	t.Error = errMsg
	t.UpdatedAt = time.Now().UTC()
	t.LeaseExpiry = time.Time{}
	if requeue {
		t.State = StatePending
		t.Owner = ""
		return nil
	}
	t.State = StateFailed
	return nil
}

// Get returns a copy of the task with the given ID, if it exists.
func (b *Board) Get(id string) (Task, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	t, ok := b.tasks[id]
	if !ok {
		return Task{}, false
	}
	return *t, true
}

// List returns a snapshot copy of every task in insertion order.
func (b *Board) List() []Task {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]Task, 0, len(b.order))
	for _, id := range b.order {
		out = append(out, *b.tasks[id])
	}
	return out
}

// Stats returns a point-in-time count of tasks by state.
func (b *Board) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()

	s := Stats{Total: len(b.order)}
	for _, id := range b.order {
		switch b.tasks[id].State {
		case StatePending:
			s.Pending++
		case StateClaimed:
			s.Claimed++
		case StateDone:
			s.Done++
		case StateFailed:
			s.Failed++
		}
	}
	return s
}

// Remaining returns the number of tasks still in flight: pending plus claimed.
func (b *Board) Remaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := 0
	for _, id := range b.order {
		switch b.tasks[id].State {
		case StatePending, StateClaimed:
			n++
		}
	}
	return n
}

// newID returns a short random hex identifier, with a timestamp fallback so
// ID generation can never fail.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
