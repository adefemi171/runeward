package webhook

// Policy mirrors the enforceable fields of a ClusterPolicy spec as a plain
// value type, so the decision logic can be tested without a cluster.
// The profile/namespace lists are glob patterns; empty means no constraint.
type Policy struct {
	AllowedProfiles   []string
	DeniedProfiles    []string
	AllowedNamespaces []string
	// RequiredLabels are label keys that must be present on the resource.
	RequiredLabels []string
	// DefaultProfile is applied (mutating) when spec.profile is empty.
	DefaultProfile string
}

// Decide evaluates an admission request against every policy. If profileName
// is empty, the first policy with a DefaultProfile supplies it; the effective
// profile, namespace, and labels are then validated, first violation wins.
// mutatedProfile always reflects the effective profile, so the caller applies
// it when it differs from the incoming profileName.
func Decide(policies []Policy, namespace string, labels map[string]string, profileName string) (allowed bool, mutatedProfile string, reason string) {
	effective := profileName
	if effective == "" {
		for _, p := range policies {
			if p.DefaultProfile != "" {
				effective = p.DefaultProfile
				break
			}
		}
	}

	for _, p := range policies {
		// Denied profiles take precedence over allowed.
		for _, pat := range p.DeniedProfiles {
			if matchGlob(pat, effective) {
				return false, effective, "profile " + quote(effective) + " is denied by cluster policy (matched " + quote(pat) + ")"
			}
		}
		if len(p.AllowedProfiles) > 0 && !matchAny(p.AllowedProfiles, effective) {
			return false, effective, "profile " + quote(effective) + " is not in the cluster policy allowed list"
		}
		// Cluster-scoped resources (empty namespace) skip the namespace
		// allowlist.
		if namespace != "" && len(p.AllowedNamespaces) > 0 && !matchAny(p.AllowedNamespaces, namespace) {
			return false, effective, "namespace " + quote(namespace) + " is not permitted by cluster policy"
		}
		for _, key := range p.RequiredLabels {
			if _, ok := labels[key]; !ok {
				return false, effective, "required label " + quote(key) + " is missing (cluster policy)"
			}
		}
	}

	return true, effective, ""
}

// matchAny reports whether s matches at least one glob pattern.
func matchAny(patterns []string, s string) bool {
	for _, pat := range patterns {
		if matchGlob(pat, s) {
			return true
		}
	}
	return false
}

// quote wraps s in double quotes for admission messages.
func quote(s string) string { return "\"" + s + "\"" }

// matchGlob reports whether s matches pattern as an anchored, full-string
// glob. '*' matches any run of characters and '?' exactly one, both including
// '/'. Local copy of the matcher in internal/policy so this package stays
// self-contained.
func matchGlob(pattern, s string) bool {
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
			pi = star + 1
			starMark++
			si = starMark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
