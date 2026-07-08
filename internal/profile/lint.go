package profile

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Runewardd/runeward/internal/egress"
)

// Severity levels a [Finding] can carry.
const (
	// SeverityError marks a problem that should fail validation. In strict
	// runtime terms these are fail-closed: the profile will not behave as its
	// author intends (or will refuse to run) if shipped as-is.
	SeverityError = "error"
	// SeverityWarn marks a likely footgun that still lets the profile run.
	SeverityWarn = "warn"
)

// Finding is a single lint result. Field is a dotted/indexed path into the
// profile (e.g. "host.image", "env[2].op", "policy[1]") so the operator can
// locate the offending stanza; Message explains the problem.
type Finding struct {
	Severity string
	Field    string
	Message  string
}

// Lint statically inspects a resolved profile and returns findings in a
// stable, deterministic order (top-level fields first, then env, network, and
// policy stanzas in declaration order). It performs no network I/O; the only
// side effect is stat-ing local paths referenced by the profile (env files and
// host.copy_from) to warn about ones that are missing.
//
// Lint is intentionally decoupled from Profile.Validate: Validate enforces the
// hard invariants that make a profile parseable, while Lint surfaces the softer
// "this probably isn't what you meant" problems on top of an already-valid
// profile. Because Lint operates on the struct directly it can also be run on
// profiles built in memory (e.g. tests) that never touched disk.
func Lint(p *Profile) []Finding {
	if p == nil {
		return nil
	}
	var out []Finding
	add := func(sev, field, msg string) {
		out = append(out, Finding{Severity: sev, Field: field, Message: msg})
	}

	// host.image: an image is effectively always required to launch a sandbox.
	// The loader defaults it, so an empty value only reaches here for profiles
	// built in memory, but flag it so callers that lint pre-default structs
	// still catch the omission.
	if strings.TrimSpace(p.Host.Image) == "" {
		add(SeverityWarn, "host.image", "no image set; an image is usually required to launch a sandbox")
	}

	// host.copy_from: warn on a source directory that isn't present on disk.
	if cf := p.Host.CopyFrom; cf != "" && !pathExists(cf) {
		add(SeverityWarn, "host.copy_from", fmt.Sprintf("copy_from path %q does not exist", cf))
	}

	lintHostFootguns(p, add)
	lintEnv(p, add)
	lintNetwork(p, add)
	lintPolicy(p, add)

	return out
}

// lintEnv flags unresolved secret references, missing files, and duplicate
// names in the [[env]] table.
func lintEnv(p *Profile, add func(sev, field, msg string)) {
	seen := make(map[string]int, len(p.Env))
	for i, e := range p.Env {
		field := fmt.Sprintf("env[%d]", i)

		if e.Name != "" {
			if first, dup := seen[e.Name]; dup {
				add(SeverityError, field+".name",
					fmt.Sprintf("duplicate env name %q (first defined at env[%d]); the later value silently wins", e.Name, first))
			} else {
				seen[e.Name] = i
			}
		}

		// op:// references are resolved at runtime and are fail-closed: a
		// profile that depends on one cannot be validated as safe statically,
		// and will refuse (or fail) to inject the value if resolution breaks.
		if e.Op != "" {
			add(SeverityError, field+".op",
				fmt.Sprintf("env %q uses an unresolved 1Password reference (%s); it is fail-closed at runtime and cannot be validated statically", e.Name, e.Op))
		}

		// file sources are read from the operator's machine; a missing path
		// means the value won't resolve when the profile is used from here.
		if e.File != "" && !pathExists(e.File) {
			add(SeverityWarn, field+".file",
				fmt.Sprintf("env %q reads from file %q which does not exist", e.Name, e.File))
		}
	}
}

func lintHostFootguns(p *Profile, add func(sev, field, msg string)) {
	if p.Network.StrictEgress() {
		if uid, ok := numericUID(p.Host.User); ok && uid == egress.StrictProxyUID {
			add(SeverityError, "host.user",
				fmt.Sprintf("host.user uid %d is reserved for strict egress interception; choose a different uid", egress.StrictProxyUID))
		}
	}

	if !p.Host.ReadOnly && (p.Network.StrictEgress() || p.Host.RuntimeClass != "") {
		add(SeverityWarn, "host.read_only",
			"host.read_only is false while stricter isolation settings are enabled; writable rootfs increases tamper surface")
	}

	if !isRootUser(p.Host.User) {
		return
	}
	for i, f := range p.Files {
		if isBroadProjectionPath(f.Path) {
			add(SeverityWarn, fmt.Sprintf("file[%d].path", i),
				fmt.Sprintf("running as root with broad file projection target %q increases write blast radius", f.Path))
		}
	}
}

// lintNetwork flags egress policies that can't do anything useful: a deny
// default with no allow rules (nothing can leave), and rules that a prior rule
// already fully shadows (first-match-wins, so the later rule never fires).
func lintNetwork(p *Profile, add func(sev, field, msg string)) {
	rules := p.Network.Rules

	if p.Network.DenyByDefault() {
		allow := 0
		for _, r := range rules {
			if isAllowVerdict(r.Verdict) {
				allow++
			}
		}
		if allow == 0 {
			if p.Network.StrictEgress() {
				add(SeverityWarn, "network.enforce",
					"strict egress is enabled but there are no allow rules; all outbound traffic is blocked")
			} else {
				add(SeverityWarn, "network.default",
					"network.default is \"deny\" but there are no allow rules; nothing can egress")
			}
		}
	}

	// A hostname selector matches exactly one host (or one "*." wildcard); it is
	// not a list. A comma or space means the author meant several hosts but got
	// a single literal that can never match, silently blocking intended traffic.
	for i, r := range rules {
		h := strings.TrimSpace(r.Hostname)
		if h != "" && strings.ContainsAny(h, ", \t") {
			add(SeverityError, fmt.Sprintf("network.rule[%d].hostname", i),
				fmt.Sprintf("hostname %q contains a comma or space; a rule matches exactly one host — use a separate [[network.rule]] per host (wildcards like *.example.com are allowed)", r.Hostname))
		}
	}

	// First-match-wins: rule j is unreachable when an earlier rule i matches a
	// superset of j's targets.
	for j := range rules {
		for i := 0; i < j; i++ {
			if networkRuleShadows(rules[i], rules[j]) {
				add(SeverityWarn, fmt.Sprintf("network.rule[%d]", j),
					fmt.Sprintf("unreachable: network.rule[%d] already matches these targets (first match wins)", i))
				break
			}
		}
	}
}

// lintPolicy flags invalid verdicts and [[policy]] rules that an earlier
// catch-all rule for the same tool already decides.
func lintPolicy(p *Profile, add func(sev, field, msg string)) {
	rules := p.Policy
	if len(rules) == 0 && (p.PolicyEngine == "" || p.PolicyEngine == "builtin") {
		add(SeverityWarn, "policy",
			"no [[policy]] rules configured; this relies on implicit allow-by-default behavior")
	}
	for i, r := range rules {
		field := fmt.Sprintf("policy[%d]", i)
		if !validVerdict(r.Verdict) {
			if r.Verdict == "" {
				add(SeverityError, field, "policy rule has no verdict (want allow, deny, or require-approval)")
			} else {
				add(SeverityError, field, fmt.Sprintf("policy rule has invalid verdict %q (want allow, deny, or require-approval)", r.Verdict))
			}
		}
	}

	for j := range rules {
		for i := 0; i < j; i++ {
			if policyRuleShadows(rules[i], rules[j]) {
				add(SeverityError, fmt.Sprintf("policy[%d]", j),
					fmt.Sprintf("unreachable: policy[%d] is a catch-all for tool %q and decides first (first match wins)", i, ruleToolLabel(rules[i].Tool)))
				break
			}
		}
	}
}

// policyRuleShadows reports whether earlier rule a matches every action later
// rule b could match, making b unreachable under first-match evaluation. It is
// deliberately conservative: it only fires when a is a genuine catch-all for a
// tool that covers b's tool, so it never reports a false unreachable.
func policyRuleShadows(a, b PolicyRule) bool {
	if !toolCovers(a.Tool, b.Tool) {
		return false
	}
	// a must match any primary argument...
	if !isCatchAllGlob(a.Match) {
		return false
	}
	// ...and impose no argv constraint, or it wouldn't match all of b's actions.
	if !isCatchAllGlob(a.MatchArgv) {
		return false
	}
	return true
}

// toolCovers reports whether a rule tool a matches every action tool b matches.
func toolCovers(a, b string) bool {
	return a == "*" || a == b
}

// isCatchAllGlob reports whether a glob field matches anything: an empty field
// (no constraint) or a bare "*".
func isCatchAllGlob(s string) bool {
	return s == "" || s == "*"
}

// ruleToolLabel renders a tool for a message, spelling out the wildcard.
func ruleToolLabel(t string) string {
	if t == "*" {
		return "* (any)"
	}
	return t
}

// networkRuleShadows reports whether earlier network rule a matches a superset
// of later rule b's targets. Hostname and CIDR selectors are compared
// independently; a rule with neither selector matches nothing and never
// shadows.
func networkRuleShadows(a, b NetworkRule) bool {
	if b.Hostname != "" && a.Hostname != "" && hostnamePatternCovers(a.Hostname, b.Hostname) {
		return true
	}
	if b.CIDR != "" && a.CIDR != "" && cidrCovers(a.CIDR, b.CIDR) {
		return true
	}
	return false
}

// hostnamePatternCovers reports whether hostname pattern a matches every
// hostname that pattern b matches. It mirrors the egress matcher's semantics:
// exact hosts or a single leading "*." wildcard.
func hostnamePatternCovers(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	suffix, ok := strings.CutPrefix(a, "*.")
	if !ok {
		// a is an exact host: it only covers itself, already handled above.
		return false
	}
	if bSuffix, ok := strings.CutPrefix(b, "*."); ok {
		// b is itself a wildcard: covered when its suffix sits under a's.
		return bSuffix == suffix || strings.HasSuffix(bSuffix, "."+suffix)
	}
	// b is an exact host under a's wildcard suffix.
	return strings.HasSuffix(b, "."+suffix) && len(b) > len(suffix)+1
}

// cidrCovers reports whether CIDR a fully contains CIDR b.
func cidrCovers(a, b string) bool {
	_, aNet, err := net.ParseCIDR(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	bIP, bNet, err := net.ParseCIDR(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	aOnes, aBits := aNet.Mask.Size()
	bOnes, bBits := bNet.Mask.Size()
	if aBits != bBits || aOnes > bOnes {
		return false
	}
	return aNet.Contains(bIP)
}

// isAllowVerdict reports whether a network rule verdict permits traffic. An
// empty verdict defaults to allow (matching backend translation).
func isAllowVerdict(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "" || v == "allow"
}

// validVerdict reports whether v is one of the recognized policy verdicts.
func validVerdict(v Verdict) bool {
	switch v {
	case VerdictAllow, VerdictDeny, VerdictRequireApprove:
		return true
	default:
		return false
	}
}

// pathExists reports whether path (with a leading "~/" expanded to the home
// directory) is present on disk.
func pathExists(path string) bool {
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	_, err := os.Stat(path)
	return err == nil
}

func numericUID(user string) (int, bool) {
	u := strings.TrimSpace(user)
	if u == "" {
		return 0, false
	}
	if i := strings.Index(u, ":"); i >= 0 {
		u = u[:i]
	}
	if u == "" {
		return 0, false
	}
	for _, r := range u {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	id, err := strconv.Atoi(u)
	if err != nil {
		return 0, false
	}
	return id, true
}

func isRootUser(user string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	if u == "" || u == "root" {
		return true
	}
	uid, ok := numericUID(u)
	return ok && uid == 0
}

func isBroadProjectionPath(pth string) bool {
	clean := path.Clean(strings.TrimSpace(pth))
	return path.IsAbs(clean)
}
