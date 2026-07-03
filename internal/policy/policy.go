// Package policy implements runeward's authority engine and cost/loop
// guardrails. Engine evaluates an Action against an ordered rule list,
// strictly first-match-wins: there is deliberately no deny-precedence pass,
// so the operator controls precedence through rule ordering. Guard caps
// wall-clock time, exec count, and egress while detecting failure loops.
package policy

import (
	"github.com/adefemi171/runeward/internal/profile"
)

// Action is a single tool invocation the engine is asked to authorize.
type Action struct {
	// Tool is the action surface, e.g. "shell", "file.read", "net".
	Tool string
	// Arg is the command line, path, or hostname the tool acts on.
	Arg string
}

// Evaluator renders a Decision for an Action, so the control plane can select
// an engine per profile without caring which is in use.
type Evaluator interface {
	Evaluate(Action) Decision
}

// Decision is the outcome of evaluating an [Action].
type Decision struct {
	Verdict profile.Verdict
	Reason  string
	// Rule is the rule that produced this decision, nil when the engine fell
	// back to its default verdict.
	Rule *profile.PolicyRule
}

// Engine evaluates actions against an ordered rule set with a default verdict.
type Engine struct {
	rules []profile.PolicyRule
	def   profile.Verdict
}

// New builds an Engine from an ordered rule slice and a default verdict
// (allow when empty). The rules slice is retained by reference; don't mutate
// it afterwards.
func New(rules []profile.PolicyRule, def profile.Verdict) *Engine {
	if def == "" {
		def = profile.VerdictAllow
	}
	return &Engine{rules: rules, def: def}
}

// Evaluate renders a Decision for a; first matching rule wins. A rule matches
// when its Tool equals a.Tool (or is "*") and a.Arg matches its glob (empty
// Match matches anything). No match returns the default verdict with a nil
// Rule.
func (e *Engine) Evaluate(a Action) Decision {
	for i := range e.rules {
		r := &e.rules[i]
		if !toolMatches(r.Tool, a.Tool) {
			continue
		}
		if r.Match != "" && !matchGlob(r.Match, a.Arg) {
			continue
		}
		return Decision{Verdict: r.Verdict, Reason: r.Reason, Rule: r}
	}
	return Decision{Verdict: e.def, Reason: "", Rule: nil}
}

func toolMatches(ruleTool, actionTool string) bool {
	return ruleTool == "*" || ruleTool == actionTool
}

// matchGlob reports whether s matches pattern as an anchored, full-string
// glob. '*' matches any run of characters and '?' exactly one; unlike
// filepath.Match, both cross '/'. Linear backtracking, no allocations.
func matchGlob(pattern, s string) bool {
	// star/starMark remember the last '*' position and where in s it started
	// matching, so we can backtrack.
	var (
		si, pi   int
		star     = -1
		starMark int
	)
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			si++
			pi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			starMark = si
			pi++
		case star != -1:
			// Mismatch: let the last '*' absorb one more character of s.
			pi = star + 1
			starMark++
			si = starMark
		default:
			return false
		}
	}
	// Consume any trailing '*' in the pattern.
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
