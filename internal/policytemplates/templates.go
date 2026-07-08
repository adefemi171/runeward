// Package policytemplates provides ready-made profile snippets for common
// security controls. Each template is a complete, valid slice of profile TOML
// (policy rules, network allowlists, or host hardening) that a user can paste
// into a runeward profile instead of authoring policy from scratch.
//
// The rendered TOML unmarshals cleanly into profile.Profile, so a template can
// be dropped straight into a profile file. Templates are addressed by a short,
// stable name; use Names to enumerate them and Render to obtain the body.
package policytemplates

import (
	"fmt"
	"sort"
)

// Template is a named, ready-to-paste profile snippet.
type Template struct {
	// Name is the short, stable identifier used to look the template up.
	Name string
	// Title is a one-line human label.
	Title string
	// Description explains what the snippet enforces and when to reach for it.
	Description string
	// TOML is the rendered profile body, with explanatory comments.
	TOML string
}

// templates is the registry keyed by Name. Bodies are trimmed to a single
// trailing newline by init so Render output is deterministic.
var templates = map[string]Template{
	"block-prod": {
		Name:        "block-prod",
		Title:       "Block production-mutating actions",
		Description: "Deny terraform/kubectl commands that mutate production, refuse egress to prod-looking hosts, and require approval for recursive force deletes.",
		TOML: `# block-prod — refuse production-mutating commands and egress to prod hosts.
# Paste these rules into a profile. They use match_argv (a glob on argv[0], the
# executable) so wrappers like ` + "`sh -c 'terraform ...'`" + ` or an absolute
# path such as /usr/local/bin/terraform cannot slip past a match on the joined
# command line. Builtin rules are first-match, so the specific denials below win.

# Terraform state mutations are blocked outright; run plans, not applies.
[[policy]]
tool       = "shell"
match_argv = "*terraform"
match      = "*apply*"
verdict    = "deny"
reason     = "terraform apply is blocked by policy; use plan only"

[[policy]]
tool       = "shell"
match_argv = "*terraform"
match      = "*destroy*"
verdict    = "deny"
reason     = "terraform destroy is blocked by policy"

# kubectl against a prod context or namespace is denied.
[[policy]]
tool       = "shell"
match_argv = "*kubectl"
match      = "*prod*"
verdict    = "deny"
reason     = "kubectl against prod contexts is blocked"

# Recursive force deletes always need a human in the loop.
[[policy]]
tool       = "shell"
match_argv = "*rm"
match      = "*-rf*"
verdict    = "require-approval"
reason     = "recursive force delete must be reviewed"

# Egress to production-looking hosts is refused. Egress rules are first-match,
# so keep this deny rule before any allowlist entries you add later.
[network]
default = "deny"

[[network.rule]]
verdict  = "deny"
hostname = "*.prod.internal, *.prod.svc, prod.*"
`,
	},
	"pii-egress": {
		Name:        "pii-egress",
		Title:       "Lock down egress and sensitive writes for PII tasks",
		Description: "Deny-by-default network with a tiny allowlist, plus require-approval on writes to credential and key-material paths.",
		TOML: `# pii-egress — lock egress to a tiny allowlist and gate writes to sensitive
# paths. Use for tasks that touch PII: nothing leaves the sandbox except the
# hosts you name, and any write to secret or credential material pauses for a
# human to approve.

[network]
default = "deny"

# Only these destinations are reachable; everything else is dropped.
[[network.rule]]
verdict  = "allow"
hostname = "api.openai.com, api.anthropic.com"

[[network.rule]]
verdict  = "allow"
hostname = "*.githubusercontent.com"

# Writes to key material and cloud credentials must be approved.
[[policy]]
tool    = "file.write"
match   = "**/.ssh/*"
verdict = "require-approval"
reason  = "write to SSH key material must be reviewed"

[[policy]]
tool    = "file.write"
match   = "**/.aws/*"
verdict = "require-approval"
reason  = "write to AWS credentials must be reviewed"

[[policy]]
tool    = "file.write"
match   = "/etc/*"
verdict = "require-approval"
reason  = "write outside the workspace must be reviewed"
`,
	},
	"package-approval": {
		Name:        "package-approval",
		Title:       "Require approval for package installs",
		Description: "Require a human to approve apt/apt-get/npm/pip/pipx/go install commands, and allow everything else to run.",
		TOML: `# package-approval — let commands run freely but require a human to approve any
# package installation. match_argv pins the executable (argv[0]) so wrappers and
# absolute paths still match; the trailing allow rule lets everything else run.
# Builtin rules are first-match, so keep the broad allow rule last.

[[policy]]
tool       = "shell"
match_argv = "*apt-get"
match      = "*install*"
verdict    = "require-approval"
reason     = "apt-get install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*apt"
match      = "*install*"
verdict    = "require-approval"
reason     = "apt install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*npm"
match      = "*install*"
verdict    = "require-approval"
reason     = "npm install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*pip"
match      = "*install*"
verdict    = "require-approval"
reason     = "pip install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*pipx"
match      = "*install*"
verdict    = "require-approval"
reason     = "pipx install must be approved"

[[policy]]
tool       = "shell"
match_argv = "*go"
match      = "install*"
verdict    = "require-approval"
reason     = "go install must be approved"

# Anything that is not a package install is allowed through.
[[policy]]
tool    = "shell"
match   = "*"
verdict = "allow"
`,
	},
	"read-only-fs": {
		Name:        "read-only-fs",
		Title:       "Read-only root filesystem",
		Description: "Mount the root filesystem read-only, deny writes outside the workspace, and block chmod/chown escalation.",
		TOML: `# read-only-fs — mount the root filesystem read-only and keep writes confined to
# the workspace. Only /workspace (and the runtime's writable /tmp) may be
# written; permission and ownership escalation is refused. Builtin rules are
# first-match, so the explicit workspace allow comes before the broad deny.

[host]
# Mount the container root filesystem read-only. /tmp and /workspace stay
# writable; workloads that must write elsewhere have to opt out.
read_only = true

# The workspace is the only writable tree; allow it explicitly first.
[[policy]]
tool    = "file.write"
match   = "/workspace/**"
verdict = "allow"
reason  = "the workspace is the only writable location"

# Any other write is refused on a read-only filesystem.
[[policy]]
tool    = "file.write"
match   = "*"
verdict = "deny"
reason  = "root filesystem is read-only; write inside /workspace"

# Permission and ownership escalation is blocked regardless of wrapper or path.
[[policy]]
tool       = "shell"
match_argv = "*chmod"
match      = "*"
verdict    = "deny"
reason     = "chmod escalation is blocked on a read-only filesystem"

[[policy]]
tool       = "shell"
match_argv = "*chown"
match      = "*"
verdict    = "deny"
reason     = "chown escalation is blocked on a read-only filesystem"
`,
	},
	"least-privilege-egress": {
		Name:        "least-privilege-egress",
		Title:       "Least-privilege egress allowlist",
		Description: "Deny-by-default egress with a couple of example allow rules and comments showing how to extend the allowlist.",
		TOML: `# least-privilege-egress — start from deny-by-default egress and open only what
# the task needs. Add one [[network.rule]] per destination. Hostnames support
# *.wildcards and comma-separated lists; use cidr for IP ranges.

[network]
default = "deny"

# enforce = "strict" adds kernel-level iptables redirection on the k8s backend
# (the default cooperative HTTP(S)_PROXY is bypassable). Ignored by docker.
enforce = "strict"

# Example: reach a model API.
[[network.rule]]
verdict  = "allow"
hostname = "api.openai.com"

# Example: allow a whole CDN via wildcard.
[[network.rule]]
verdict  = "allow"
hostname = "*.githubusercontent.com"

# Example: allow an internal IP range by CIDR (uncomment and edit).
# [[network.rule]]
# verdict = "allow"
# cidr    = "10.0.0.0/8"
`,
	},
}

// Names returns the template names in sorted order.
func Names() []string {
	names := make([]string, 0, len(templates))
	for name := range templates {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Get returns the template registered under name. The bool is false when no
// such template exists.
func Get(name string) (Template, bool) {
	t, ok := templates[name]
	return t, ok
}

// Render returns the TOML body for the named template, ready to paste into a
// profile. It returns an error when the name is unknown.
func Render(name string) (string, error) {
	t, ok := templates[name]
	if !ok {
		return "", fmt.Errorf("policytemplates: unknown template %q", name)
	}
	return t.TOML, nil
}

// All returns every template, sorted by Name.
func All() []Template {
	out := make([]Template, 0, len(templates))
	for _, name := range Names() {
		out = append(out, templates[name])
	}
	return out
}
