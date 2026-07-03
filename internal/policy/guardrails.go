package policy

import (
	"errors"
	"sync"
	"time"

	"github.com/adefemi171/runeward/internal/profile"
)

// Sentinel errors returned by [Guard].
var (
	ErrWallClock    = errors.New("policy: wall-clock deadline exceeded")
	ErrMaxExecs     = errors.New("policy: max execs exceeded")
	ErrEgressBudget = errors.New("policy: egress budget exceeded")
	ErrLoopDetected = errors.New("policy: runaway loop detected")
)

// Guard enforces per-session cost and loop guardrails from profile.Limits.
// All limits are opt-in: a zero/empty value disables that guard. Safe for
// concurrent use.
type Guard struct {
	wallClock   time.Duration // 0 = disabled
	maxExecs    int           // 0 = unlimited
	egressLimit int           // 0 = unlimited
	loopWindow  time.Duration // 0 = loop detection disabled
	loopThresh  int           // 0 = loop detection disabled

	now func() time.Time // injectable clock for testing

	mu        sync.Mutex
	started   bool
	startTime time.Time
	execs     int
	egress    int
	loopKey   string                 // key that tripped the loop, if any
	tripped   bool                   // whether a loop has tripped
	failures  map[string][]time.Time // sliding window of failure timestamps per key
}

// NewGuard builds a Guard from limits. It errors if WallClock or LoopWindow
// is set but not a valid duration string.
func NewGuard(limits profile.Limits) (*Guard, error) {
	var (
		wall time.Duration
		loop time.Duration
		err  error
	)
	if limits.WallClock != "" {
		if wall, err = time.ParseDuration(limits.WallClock); err != nil {
			return nil, err
		}
	}
	if limits.LoopWindow != "" {
		if loop, err = time.ParseDuration(limits.LoopWindow); err != nil {
			return nil, err
		}
	}
	return &Guard{
		wallClock:   wall,
		maxExecs:    limits.MaxExecs,
		egressLimit: limits.EgressRequests,
		loopWindow:  loop,
		loopThresh:  limits.LoopThreshold,
		now:         time.Now,
		failures:    make(map[string][]time.Time),
	}, nil
}

// Start records the session start time for wall-clock enforcement. Only the
// first call takes effect.
func (g *Guard) Start() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.started {
		g.started = true
		g.startTime = g.now()
	}
}

// CheckExec must be called before each tool invocation. It checks the
// wall-clock deadline, a tripped loop, and the exec budget in that order,
// incrementing the exec counter only when the call is permitted.
func (g *Guard) CheckExec() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.wallClock > 0 && g.started {
		if g.now().Sub(g.startTime) >= g.wallClock {
			return ErrWallClock
		}
	}
	if g.tripped {
		return ErrLoopDetected
	}
	if g.maxExecs > 0 && g.execs >= g.maxExecs {
		return ErrMaxExecs
	}
	g.execs++
	return nil
}

// CheckEgress must be called before each outbound request. It returns
// ErrEgressBudget once the budget is exhausted.
func (g *Guard) CheckEgress() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.egressLimit > 0 && g.egress >= g.egressLimit {
		return ErrEgressBudget
	}
	g.egress++
	return nil
}

// RecordOutcome records the result of an action identified by key. A success
// clears the key's failure window; failures accumulate in a sliding window,
// and once a key hits loopThresh failures within loopWindow the detector
// trips and stays tripped until Reset.
func (g *Guard) RecordOutcome(key string, failed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !failed {
		delete(g.failures, key)
		return
	}
	if g.loopWindow <= 0 || g.loopThresh <= 0 {
		return
	}

	now := g.now()
	cutoff := now.Add(-g.loopWindow)

	// Drop timestamps that have aged out of the window.
	times := g.failures[key]
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	g.failures[key] = kept

	if len(kept) >= g.loopThresh {
		g.tripped = true
		g.loopKey = key
	}
}

// LoopTripped reports whether a failure loop has been detected and, if so,
// the key responsible.
func (g *Guard) LoopTripped() (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tripped, g.loopKey
}

// Reset clears counters, failure windows, and tripped state so the Guard can
// be reused for a fresh session. The parsed limits are retained.
func (g *Guard) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.started = false
	g.startTime = time.Time{}
	g.execs = 0
	g.egress = 0
	g.tripped = false
	g.loopKey = ""
	g.failures = make(map[string][]time.Time)
}
