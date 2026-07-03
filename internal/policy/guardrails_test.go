package policy

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/adefemi171/runeward/internal/profile"
)

// fakeClock is a manually advanced clock for deterministic tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(0, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestNewGuardBadDurations(t *testing.T) {
	if _, err := NewGuard(profile.Limits{WallClock: "not-a-duration"}); err == nil {
		t.Error("expected error for bad WallClock")
	}
	if _, err := NewGuard(profile.Limits{LoopWindow: "nope"}); err == nil {
		t.Error("expected error for bad LoopWindow")
	}
}

func TestMaxExecs(t *testing.T) {
	g, err := NewGuard(profile.Limits{MaxExecs: 3})
	if err != nil {
		t.Fatal(err)
	}
	g.Start()
	for i := 0; i < 3; i++ {
		if err := g.CheckExec(); err != nil {
			t.Fatalf("exec %d unexpectedly blocked: %v", i, err)
		}
	}
	if err := g.CheckExec(); !errors.Is(err, ErrMaxExecs) {
		t.Fatalf("4th exec: got %v, want ErrMaxExecs", err)
	}
}

func TestMaxExecsUnlimited(t *testing.T) {
	g, _ := NewGuard(profile.Limits{})
	g.Start()
	for i := 0; i < 1000; i++ {
		if err := g.CheckExec(); err != nil {
			t.Fatalf("exec %d blocked when unlimited: %v", i, err)
		}
	}
}

func TestEgressBudget(t *testing.T) {
	g, _ := NewGuard(profile.Limits{EgressRequests: 2})
	if err := g.CheckEgress(); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckEgress(); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckEgress(); !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("3rd egress: got %v, want ErrEgressBudget", err)
	}
}

func TestWallClock(t *testing.T) {
	clk := newFakeClock()
	g, err := NewGuard(profile.Limits{WallClock: "10ms"})
	if err != nil {
		t.Fatal(err)
	}
	g.now = clk.now
	g.Start()

	if err := g.CheckExec(); err != nil {
		t.Fatalf("exec before deadline blocked: %v", err)
	}
	clk.advance(10 * time.Millisecond)
	if err := g.CheckExec(); !errors.Is(err, ErrWallClock) {
		t.Fatalf("exec after deadline: got %v, want ErrWallClock", err)
	}
}

func TestWallClockDisabledWithoutStart(t *testing.T) {
	clk := newFakeClock()
	g, _ := NewGuard(profile.Limits{WallClock: "10ms"})
	g.now = clk.now
	// No Start() call, so wall-clock enforcement is inert.
	clk.advance(time.Hour)
	if err := g.CheckExec(); err != nil {
		t.Fatalf("wall-clock enforced without Start: %v", err)
	}
}

func TestLoopDetectionTripsWithinWindow(t *testing.T) {
	clk := newFakeClock()
	g, err := NewGuard(profile.Limits{LoopWindow: "1s", LoopThreshold: 3})
	if err != nil {
		t.Fatal(err)
	}
	g.now = clk.now

	g.RecordOutcome("k", true)
	clk.advance(100 * time.Millisecond)
	g.RecordOutcome("k", true)
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("tripped before reaching threshold")
	}
	clk.advance(100 * time.Millisecond)
	g.RecordOutcome("k", true) // 3rd within window

	tripped, key := g.LoopTripped()
	if !tripped || key != "k" {
		t.Fatalf("expected loop trip on key k, got tripped=%v key=%q", tripped, key)
	}
	if err := g.CheckExec(); !errors.Is(err, ErrLoopDetected) {
		t.Fatalf("CheckExec after loop: got %v, want ErrLoopDetected", err)
	}
}

func TestLoopDetectionSpacedBeyondWindow(t *testing.T) {
	clk := newFakeClock()
	g, _ := NewGuard(profile.Limits{LoopWindow: "1s", LoopThreshold: 3})
	g.now = clk.now

	// Failures spaced beyond the window never accumulate to the threshold.
	for i := 0; i < 5; i++ {
		g.RecordOutcome("k", true)
		clk.advance(2 * time.Second)
	}
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("loop tripped despite failures spaced beyond window")
	}
}

func TestLoopDetectionBelowThreshold(t *testing.T) {
	clk := newFakeClock()
	g, _ := NewGuard(profile.Limits{LoopWindow: "1s", LoopThreshold: 3})
	g.now = clk.now

	g.RecordOutcome("k", true)
	g.RecordOutcome("k", true) // only 2, threshold is 3
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("loop tripped below threshold")
	}
}

func TestLoopDetectionSuccessResetsWindow(t *testing.T) {
	clk := newFakeClock()
	g, _ := NewGuard(profile.Limits{LoopWindow: "1s", LoopThreshold: 3})
	g.now = clk.now

	g.RecordOutcome("k", true)
	g.RecordOutcome("k", true)
	g.RecordOutcome("k", false) // success clears the window
	g.RecordOutcome("k", true)
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("loop tripped after success reset the window")
	}
}

func TestLoopDetectionPerKeyIsolation(t *testing.T) {
	clk := newFakeClock()
	g, _ := NewGuard(profile.Limits{LoopWindow: "1s", LoopThreshold: 3})
	g.now = clk.now

	g.RecordOutcome("a", true)
	g.RecordOutcome("b", true)
	g.RecordOutcome("a", true)
	g.RecordOutcome("b", true)
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("distinct keys should not aggregate into a loop trip")
	}
}

func TestLoopDetectionDisabled(t *testing.T) {
	g, _ := NewGuard(profile.Limits{})
	for i := 0; i < 100; i++ {
		g.RecordOutcome("k", true)
	}
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("loop detection should be disabled without window/threshold")
	}
}

func TestReset(t *testing.T) {
	g, _ := NewGuard(profile.Limits{MaxExecs: 1, LoopWindow: "1s", LoopThreshold: 2})
	g.Start()
	_ = g.CheckExec()
	g.RecordOutcome("k", true)
	g.RecordOutcome("k", true)
	if tripped, _ := g.LoopTripped(); !tripped {
		t.Fatal("precondition: expected loop tripped")
	}

	g.Reset()
	if tripped, _ := g.LoopTripped(); tripped {
		t.Fatal("Reset should clear tripped state")
	}
	g.Start()
	if err := g.CheckExec(); err != nil {
		t.Fatalf("Reset should clear exec counter: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	g, _ := NewGuard(profile.Limits{MaxExecs: 0, EgressRequests: 0, LoopWindow: "1s", LoopThreshold: 1000})
	g.Start()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = g.CheckExec()
			_ = g.CheckEgress()
			g.RecordOutcome("shared", true)
			_, _ = g.LoopTripped()
		}(i)
	}
	wg.Wait()
}
