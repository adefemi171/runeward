package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/Runewardd/runeward/internal/profile"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// RegoEngine is an authority engine backed by an OPA/Rego module, compiled
// and prepared once at construction so a malformed policy fails fast. The
// query result may be a bare verdict string or an object
// {"verdict": ..., "reason": ...}; anything else falls back to the default
// verdict. Safe for concurrent use.
type RegoEngine struct {
	pq  rego.PreparedEvalQuery
	def profile.Verdict
}

const defaultRegoQuery = "data.runeward.decision"

// NewRego compiles and prepares module as a RegoEngine. query defaults to
// "data.runeward.decision" and def to allow. Modules use Rego v1 syntax
// (`if`/`contains`, no future.keywords import needed).
func NewRego(module, query string, def profile.Verdict) (*RegoEngine, error) {
	if def == "" {
		def = profile.VerdictAllow
	}
	if query == "" {
		query = defaultRegoQuery
	}
	r := rego.New(
		rego.Query(query),
		rego.Module("policy.rego", module),
		// The Go rego.New default is otherwise v0.
		rego.SetRegoVersion(ast.RegoV1),
	)
	pq, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("policy: prepare rego query %q: %w", query, err)
	}
	return &RegoEngine{pq: pq, def: def}, nil
}

// Evaluate runs the prepared query against {tool, arg}. Evaluation errors fail
// closed to deny; undefined results and unrecognized verdicts return the
// default verdict with a nil Rule.
func (e *RegoEngine) Evaluate(a Action) (dec Decision) {
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("policy: rego evaluation panic: %v", r)
			dec = Decision{
				Verdict: profile.VerdictDeny,
				Reason:  reason,
				Rule:    &profile.PolicyRule{Tool: a.Tool, Match: a.Arg, Verdict: profile.VerdictDeny, Reason: reason},
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	input := map[string]any{"tool": a.Tool, "arg": a.Arg}
	rs, err := e.pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		reason := fmt.Sprintf("policy: rego evaluation error: %v", err)
		return Decision{
			Verdict: profile.VerdictDeny,
			Reason:  reason,
			Rule:    &profile.PolicyRule{Tool: a.Tool, Match: a.Arg, Verdict: profile.VerdictDeny, Reason: reason},
		}
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{Verdict: e.def}
	}

	verdict, reason, ok := parseRegoResult(rs[0].Expressions[0].Value)
	if !ok {
		return Decision{Verdict: e.def}
	}
	return Decision{
		Verdict: verdict,
		Reason:  reason,
		Rule:    &profile.PolicyRule{Tool: a.Tool, Match: a.Arg, Verdict: verdict, Reason: reason},
	}
}

// parseRegoResult accepts either a bare verdict string or an object
// {"verdict": ..., "reason": ...}.
func parseRegoResult(v any) (profile.Verdict, string, bool) {
	switch val := v.(type) {
	case string:
		return validVerdict(val, "")
	case map[string]any:
		verdict, _ := val["verdict"].(string)
		reason, _ := val["reason"].(string)
		return validVerdict(verdict, reason)
	default:
		return "", "", false
	}
}

func validVerdict(s, reason string) (profile.Verdict, string, bool) {
	switch profile.Verdict(s) {
	case profile.VerdictAllow, profile.VerdictDeny, profile.VerdictRequireApprove:
		return profile.Verdict(s), reason, true
	default:
		return "", "", false
	}
}
