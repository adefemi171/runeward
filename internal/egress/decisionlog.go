package egress

import (
	"strings"
	"sync"
	"time"
)

const maxDecisionsPerSandbox = 128

// Decision is one recorded egress allow/deny outcome for dashboard inspection.
type Decision struct {
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	IP        string    `json:"ip"`
	Allow     bool      `json:"allow"`
	Reason    string    `json:"reason"`
}

type decisionRing struct {
	items []Decision
	next  int
	full  bool
}

var decisions struct {
	mu        sync.Mutex
	bySandbox map[string]*decisionRing
}

// RecordDecision appends one decision to the per-sandbox bounded in-memory log.
func RecordDecision(sandboxID, host, ip string, allow bool, reason string) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return
	}
	host = strings.TrimSpace(host)
	ip = strings.TrimSpace(ip)
	reason = strings.TrimSpace(reason)

	d := Decision{
		Timestamp: time.Now().UTC(),
		Host:      host,
		IP:        ip,
		Allow:     allow,
		Reason:    reason,
	}

	decisions.mu.Lock()
	defer decisions.mu.Unlock()
	if decisions.bySandbox == nil {
		decisions.bySandbox = make(map[string]*decisionRing)
	}
	r, ok := decisions.bySandbox[sandboxID]
	if !ok {
		r = &decisionRing{items: make([]Decision, maxDecisionsPerSandbox)}
		decisions.bySandbox[sandboxID] = r
	}
	r.items[r.next] = d
	r.next = (r.next + 1) % len(r.items)
	if r.next == 0 {
		r.full = true
	}
}

// ListDecisions returns the current per-sandbox decision log, oldest to newest.
func ListDecisions(sandboxID string) []Decision {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil
	}
	decisions.mu.Lock()
	defer decisions.mu.Unlock()
	r := decisions.bySandbox[sandboxID]
	if r == nil {
		return nil
	}
	if !r.full {
		out := make([]Decision, 0, r.next)
		for i := 0; i < r.next; i++ {
			out = append(out, r.items[i])
		}
		return out
	}
	out := make([]Decision, 0, len(r.items))
	for i := r.next; i < len(r.items); i++ {
		out = append(out, r.items[i])
	}
	for i := 0; i < r.next; i++ {
		out = append(out, r.items[i])
	}
	return out
}

func sandboxIDFromLoggerPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	const marker = "runeward-egress "
	i := strings.Index(prefix, marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(prefix[i+len(marker):])
	if rest == "" {
		return ""
	}
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}
