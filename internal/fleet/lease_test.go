package fleet

import (
	"testing"
	"time"
)

func TestLeaseSweepRequeuesDeadWorker(t *testing.T) {
	b := NewBoard()
	b.SetLease(50 * time.Millisecond)
	b.Add("job")

	claimed, ok := b.Claim("worker-1")
	if !ok {
		t.Fatal("expected to claim a task")
	}
	if claimed.LeaseExpiry.IsZero() {
		t.Fatal("claim should stamp a lease expiry")
	}

	if got := b.Sweep(time.Now()); len(got) != 0 {
		t.Fatalf("premature sweep requeued %d tasks", len(got))
	}

	requeued := b.Sweep(time.Now().Add(time.Second))
	if len(requeued) != 1 {
		t.Fatalf("expected 1 requeued task, got %d", len(requeued))
	}
	got, _ := b.Get(claimed.ID)
	if got.State != StatePending {
		t.Fatalf("requeued task state = %s, want pending", got.State)
	}
	if got.Owner != "" {
		t.Fatalf("requeued task owner = %q, want empty", got.Owner)
	}
	if got.Attempts != 1 {
		t.Fatalf("attempts should be retained (1), got %d", got.Attempts)
	}
}

func TestHeartbeatExtendsLease(t *testing.T) {
	b := NewBoard()
	b.SetLease(50 * time.Millisecond)
	b.Add("job")
	c, _ := b.Claim("w1")

	time.Sleep(5 * time.Millisecond)
	hb, err := b.Heartbeat(c.ID, "w1")
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !hb.LeaseExpiry.After(c.LeaseExpiry) {
		t.Fatal("heartbeat should push the lease expiry forward")
	}

	if _, err := b.Heartbeat(c.ID, "someone-else"); err == nil {
		t.Fatal("heartbeat by wrong owner should fail")
	}
}

func TestLoadRestoresBoard(t *testing.T) {
	b := NewBoard()
	b.Add("a")
	b.Add("b")
	c, _ := b.Claim("w1")
	_ = b.Complete(c.ID, "done")

	restored := Load(b.Export(), time.Minute)
	if got := restored.Stats(); got.Total != 2 || got.Done != 1 || got.Pending != 1 {
		t.Fatalf("restored stats = %+v", got)
	}
}
