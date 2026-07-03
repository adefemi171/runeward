package fleet

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestLifecycle(t *testing.T) {
	b := NewBoard()
	added := b.Add("build")

	if added.State != StatePending {
		t.Fatalf("new task state = %s, want %s", added.State, StatePending)
	}
	if got := b.Stats(); got != (Stats{Total: 1, Pending: 1}) {
		t.Fatalf("stats after add = %+v", got)
	}

	claimed, ok := b.Claim("w1")
	if !ok {
		t.Fatal("Claim returned ok=false on non-empty board")
	}
	if claimed.ID != added.ID {
		t.Fatalf("claimed id = %q, want %q", claimed.ID, added.ID)
	}
	if claimed.State != StateClaimed || claimed.Owner != "w1" || claimed.Attempts != 1 {
		t.Fatalf("claimed task = %+v", claimed)
	}
	if got := b.Stats(); got != (Stats{Total: 1, Claimed: 1}) {
		t.Fatalf("stats after claim = %+v", got)
	}

	if err := b.Complete(claimed.ID, "ok"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	done, _ := b.Get(claimed.ID)
	if done.State != StateDone || done.Result != "ok" {
		t.Fatalf("completed task = %+v", done)
	}
	if got := b.Stats(); got != (Stats{Total: 1, Done: 1}) {
		t.Fatalf("stats after complete = %+v", got)
	}
	if r := b.Remaining(); r != 0 {
		t.Fatalf("Remaining = %d, want 0", r)
	}
}

func TestClaimEmpty(t *testing.T) {
	b := NewBoard()
	if _, ok := b.Claim("w1"); ok {
		t.Fatal("Claim on empty board returned ok=true")
	}
}

func TestFIFOClaimOrder(t *testing.T) {
	payloads := []string{"a", "b", "c", "d"}
	b := Seed(payloads)

	for _, want := range payloads {
		got, ok := b.Claim("w")
		if !ok {
			t.Fatalf("Claim returned ok=false, expected payload %q", want)
		}
		if got.Payload != want {
			t.Fatalf("FIFO order broken: got %q, want %q", got.Payload, want)
		}
	}
	if _, ok := b.Claim("w"); ok {
		t.Fatal("Claim returned ok=true after all tasks claimed")
	}
}

func TestFailRequeue(t *testing.T) {
	b := Seed([]string{"x"})
	c1, _ := b.Claim("w1")
	if c1.Attempts != 1 {
		t.Fatalf("first claim attempts = %d, want 1", c1.Attempts)
	}

	if err := b.Fail(c1.ID, "boom", true); err != nil {
		t.Fatalf("Fail requeue: %v", err)
	}
	requeued, _ := b.Get(c1.ID)
	if requeued.State != StatePending {
		t.Fatalf("requeued state = %s, want %s", requeued.State, StatePending)
	}
	if requeued.Owner != "" {
		t.Fatalf("requeued owner = %q, want empty", requeued.Owner)
	}
	if requeued.Attempts != 1 {
		t.Fatalf("requeued attempts = %d, want 1 (preserved)", requeued.Attempts)
	}
	if requeued.Error != "boom" {
		t.Fatalf("requeued error = %q, want boom", requeued.Error)
	}

	c2, ok := b.Claim("w2")
	if !ok {
		t.Fatal("requeued task was not claimable again")
	}
	if c2.Attempts != 2 {
		t.Fatalf("second claim attempts = %d, want 2 (incremented)", c2.Attempts)
	}
}

func TestFailNoRequeue(t *testing.T) {
	b := Seed([]string{"x"})
	c, _ := b.Claim("w1")

	if err := b.Fail(c.ID, "boom", false); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	failed, _ := b.Get(c.ID)
	if failed.State != StateFailed {
		t.Fatalf("failed state = %s, want %s", failed.State, StateFailed)
	}
	if got := b.Stats(); got != (Stats{Total: 1, Failed: 1}) {
		t.Fatalf("stats after fail = %+v", got)
	}
	if _, ok := b.Claim("w2"); ok {
		t.Fatal("failed (no requeue) task should not be claimable")
	}
}

func TestIllegalTransition(t *testing.T) {
	b := Seed([]string{"x"})
	pending := b.List()[0]

	err := b.Complete(pending.ID, "res")
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("Complete on pending err = %v, want ErrIllegalTransition", err)
	}

	err = b.Fail(pending.ID, "e", false)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("Fail on pending err = %v, want ErrIllegalTransition", err)
	}

	c, _ := b.Claim("w")
	if err := b.Complete(c.ID, "ok"); err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	if err := b.Complete(c.ID, "again"); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("second Complete err = %v, want ErrIllegalTransition", err)
	}
}

func TestNotFound(t *testing.T) {
	b := NewBoard()
	if _, ok := b.Get("nope"); ok {
		t.Fatal("Get on missing id returned ok=true")
	}
	if err := b.Complete("nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Complete missing err = %v, want ErrNotFound", err)
	}
	if err := b.Fail("nope", "x", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Fail missing err = %v, want ErrNotFound", err)
	}
}

func TestUniqueIDs(t *testing.T) {
	b := NewBoard()
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id := b.Add(fmt.Sprintf("p%d", i)).ID
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate generated id %q", id)
		}
		seen[id] = struct{}{}
	}
}

// TestConcurrentClaim asserts no task is ever handed to two workers and every
// task ends up done. Must pass under -race.
func TestConcurrentClaim(t *testing.T) {
	const (
		numTasks   = 1000
		numWorkers = 8
	)

	payloads := make([]string, numTasks)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("task-%d", i)
	}
	b := Seed(payloads)

	var (
		claimMu    sync.Mutex
		claimedIDs = make(map[string]struct{})
		completed  int
	)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			owner := fmt.Sprintf("w%d", id)
			for {
				task, ok := b.Claim(owner)
				if !ok {
					return
				}

				claimMu.Lock()
				if _, dup := claimedIDs[task.ID]; dup {
					claimMu.Unlock()
					t.Errorf("task %q double-claimed", task.ID)
					return
				}
				claimedIDs[task.ID] = struct{}{}
				completed++
				claimMu.Unlock()

				if err := b.Complete(task.ID, "done"); err != nil {
					t.Errorf("Complete(%q): %v", task.ID, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if completed != numTasks {
		t.Fatalf("completed %d tasks, want %d", completed, numTasks)
	}
	if len(claimedIDs) != numTasks {
		t.Fatalf("distinct claimed ids = %d, want %d", len(claimedIDs), numTasks)
	}
	if got := b.Stats(); got.Done != numTasks || got.Total != numTasks {
		t.Fatalf("final stats = %+v, want %d done", got, numTasks)
	}
	if r := b.Remaining(); r != 0 {
		t.Fatalf("Remaining = %d, want 0", r)
	}
}

// TestConcurrentClaimWithRequeue fails the first attempt on each task and
// completes the second, so every task must finish done with Attempts >= 2.
func TestConcurrentClaimWithRequeue(t *testing.T) {
	const (
		numTasks   = 500
		numWorkers = 8
	)

	payloads := make([]string, numTasks)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("task-%d", i)
	}
	b := Seed(payloads)

	var (
		mu         sync.Mutex
		failedOnce = make(map[string]bool)
	)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			owner := fmt.Sprintf("w%d", id)
			for {
				task, ok := b.Claim(owner)
				if !ok {
					return
				}
				mu.Lock()
				firstTime := !failedOnce[task.ID]
				if firstTime {
					failedOnce[task.ID] = true
				}
				mu.Unlock()

				if firstTime {
					if err := b.Fail(task.ID, "transient", true); err != nil {
						t.Errorf("Fail(%q): %v", task.ID, err)
						return
					}
					continue
				}
				if err := b.Complete(task.ID, "done"); err != nil {
					t.Errorf("Complete(%q): %v", task.ID, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if got := b.Stats(); got.Done != numTasks {
		t.Fatalf("final stats = %+v, want %d done", got, numTasks)
	}
	for _, task := range b.List() {
		if task.Attempts < 2 {
			t.Fatalf("task %q attempts = %d, want >= 2", task.ID, task.Attempts)
		}
	}
	if r := b.Remaining(); r != 0 {
		t.Fatalf("Remaining = %d, want 0", r)
	}
}
