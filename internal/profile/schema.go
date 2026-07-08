// Package profile defines the declarative profile schema and its loader.
// A profile is a named security contract for a task, resolved fresh on every
// invocation and never written back to disk. Profiles may be authored in TOML,
// YAML, or JSON; the struct tags carry identical toml and json keys so field
// spellings match across formats.
package profile

// HostType selects the execution backend a profile runs on.
type HostType string

const (
	// HostContainer runs the sandbox as a Docker/Podman container (the default).
	HostContainer HostType = "container"
	// HostK8s runs the sandbox as a Kubernetes Sandbox custom resource.
	HostK8s HostType = "k8s"
)

// Verdict is the decision a policy rule renders for a matched action.
type Verdict string

const (
	VerdictAllow          Verdict = "allow"
	VerdictDeny           Verdict = "deny"
	VerdictRequireApprove Verdict = "require-approval"
)

// Profile is the top-level resolved contract read from a <name>.{toml,yaml,json} file.
type Profile struct {
	// Name comes from the filename, not the file body.
	Name string `toml:"-" json:"-"`
	// Source is the absolute path the profile was resolved from.
	Source string `toml:"-" json:"-"`

	Host    Host         `toml:"host" json:"host"`
	Prompt  Prompt       `toml:"prompt" json:"prompt"`
	Env     []EnvVar     `toml:"env" json:"env"`
	Files   []File       `toml:"file" json:"file"`
	Network Network      `toml:"network" json:"network"`
	Policy  []PolicyRule `toml:"policy" json:"policy"`
	// PolicyDefault controls the fallback verdict when no policy rule matches.
	// Empty keeps the historical default ("allow"); set to "deny" to fail closed.
	PolicyDefault Verdict `toml:"policy_default" json:"policy_default"`
	// PolicyEngine is "" or "builtin" (the [[policy]] rules), "cel", or "rego".
	// Selecting cel or rego makes the [[policy]] rules ignored.
	PolicyEngine string     `toml:"policy_engine" json:"policy_engine"`
	CEL          []CELRule  `toml:"cel" json:"cel"`
	Rego         RegoPolicy `toml:"rego" json:"rego"`
	// PolicyBundle, when set, supersedes the inline policy fields with a signed
	// bundle pulled from an OCI registry.
	PolicyBundle *PolicyBundle `toml:"policy_bundle" json:"policy_bundle"`
	Limits       Limits        `toml:"limits" json:"limits"`
	Fleet        *Fleet        `toml:"fleet" json:"fleet"`
	Audit        Audit         `toml:"audit" json:"audit"`
	// Packages are installed only with --provision, never on the run path.
	Packages []string `toml:"packages" json:"packages"`
}

// Host declares where and how a session runs.
type Host struct {
	Type    HostType `toml:"type" json:"type"`
	Name    string   `toml:"name" json:"name"`
	Image   string   `toml:"image" json:"image"`
	User    string   `toml:"user" json:"user"`
	Workdir string   `toml:"workdir" json:"workdir"`
	// CopyFrom is a local directory copied into the workspace at creation.
	// One-time copy, never a mount; supports "~/". The image must have tar.
	CopyFrom string `toml:"copy_from" json:"copy_from"`
	// Runtime is a backend hint ("docker", "podman").
	Runtime string `toml:"runtime" json:"runtime"`
	// RuntimeClass selects a sandboxed runtime for VM-grade isolation. On k8s
	// it maps to runtimeClassName (e.g. "gvisor", "kata"); on the docker
	// backend it maps to `docker run --runtime` (e.g. "runsc", "kata-runtime").
	// The runtime must be registered with the engine or creation fails.
	RuntimeClass string `toml:"runtime_class" json:"runtime_class"`
	// ReadOnly mounts the container root filesystem read-only (with a writable
	// tmpfs at /tmp and the writable workspace). Hardens against tampering with
	// the image; workloads that write outside /workspace or /tmp must opt out.
	ReadOnly bool `toml:"read_only" json:"read_only"`
	// Seccomp selects a seccomp profile. On Docker it is a path passed to
	// `--security-opt seccomp=<path>`; on Kubernetes a path makes the pod use a
	// Localhost profile, otherwise the pod defaults to RuntimeDefault.
	Seccomp string `toml:"seccomp" json:"seccomp"`
	// AppArmor selects an AppArmor profile name (Docker: `--security-opt
	// apparmor=<name>`; Kubernetes: the container AppArmor profile).
	AppArmor string `toml:"apparmor" json:"apparmor"`
}

// Prompt is an optional system prompt, inline or sourced from a file.
type Prompt struct {
	Inline string `toml:"inline" json:"inline"`
	File   string `toml:"file" json:"file"`
}

// EnvVar is a single environment value resolved fresh per invocation.
// Value, File, and Op are mutually exclusive; set exactly one.
type EnvVar struct {
	Name string `toml:"name" json:"name"`
	// Value is a literal.
	Value string `toml:"value" json:"value"`
	// File reads the value from a path on the operator's machine.
	File string `toml:"file" json:"file"`
	// Op is a secret-manager scheme reference resolved at sandbox creation.
	// Supported: env://NAME, vault://<mount>/<path>#<field>, and op://... (the
	// latter is not built in and always fails closed). The TOML key stays "op"
	// for backward compatibility.
	Op string `toml:"op" json:"op"`
	// SecretFlag marks a literal Value as sensitive so it is redacted from the
	// ledger and API output. File/Op sources are always treated as secret.
	SecretFlag bool `toml:"secret" json:"secret"`
}

// Secret reports whether this env value carries a sensitive source or is
// explicitly flagged secret.
func (e EnvVar) Secret() bool { return e.SecretFlag || e.Op != "" || e.File != "" }

// File is projected into the sandbox, owned root:root at Mode, streamed in
// without touching host disk.
type File struct {
	Path string `toml:"path" json:"path"`
	Mode string `toml:"mode" json:"mode"`
	// File is the source path on the operator's machine; Content is the inline
	// alternative.
	File    string `toml:"file" json:"file"`
	Content string `toml:"content" json:"content"`
}

// Network is the declarative egress/ingress policy. An empty [network] block
// means fully open; Default = "deny" enables the allowlist.
type Network struct {
	Default string        `toml:"default" json:"default"`
	Rules   []NetworkRule `toml:"rule" json:"rule"`
	// Enforce: "" uses the cooperative HTTP(S)_PROXY env (bypassable);
	// "strict" (alias "l3") adds kernel-level iptables redirection on the k8s
	// backend. Ignored by the docker backend.
	Enforce string `toml:"enforce" json:"enforce"`
}

// StrictEgress reports whether L3 (kernel-level) egress enforcement is requested.
func (n Network) StrictEgress() bool {
	return n.Default == "deny" && (n.Enforce == "strict" || n.Enforce == "l3")
}

// DenyByDefault reports whether unmatched egress should be blocked.
func (n Network) DenyByDefault() bool { return n.Default == "deny" }

// NetworkRule allows or denies traffic to a hostname (supports *.wildcards).
type NetworkRule struct {
	Verdict  string `toml:"verdict" json:"verdict"`
	Hostname string `toml:"hostname" json:"hostname"`
	CIDR     string `toml:"cidr" json:"cidr"`
}

// PolicyRule maps an action to a verdict evaluated before the action executes.
type PolicyRule struct {
	// Tool matches the action surface: shell|python|node|file.read|file.write|
	// file.edit|net (supports "*").
	Tool string `toml:"tool" json:"tool"`
	// Match is a glob applied to the action's primary argument (command,
	// path, or hostname depending on Tool).
	Match string `toml:"match" json:"match"`
	// MatchArgv, when set, is a glob applied to the command's argv[0] (the
	// executable). It closes the evasion where `deny "rm*"` on the joined
	// command line is sidestepped via `sh -c 'rm ...'` or `/bin/rm`: a rule with
	// match_argv = "*/rm" or "rm" matches regardless of wrapper or path.
	MatchArgv string  `toml:"match_argv" json:"match_argv"`
	Verdict   Verdict `toml:"verdict" json:"verdict"`
	// Reason is shown to the approver and recorded in the ledger.
	Reason string `toml:"reason" json:"reason"`
}

// CELRule is one rule of a CEL policy. Expr is a boolean expression over
// `tool` and `arg` (both strings); the first true Expr renders its Verdict.
type CELRule struct {
	Expr    string  `toml:"expr" json:"expr"`
	Verdict Verdict `toml:"verdict" json:"verdict"`
	Reason  string  `toml:"reason" json:"reason"`
}

// UsesCEL reports whether the profile selects the CEL authority engine.
func (p *Profile) UsesCEL() bool { return p.PolicyEngine == "cel" }

// RegoPolicy configures the Rego (OPA) engine. Set exactly one of Module
// (inline) or File. Query defaults to "data.runeward.decision".
type RegoPolicy struct {
	Module string `toml:"module" json:"module"`
	File   string `toml:"file" json:"file"`
	Query  string `toml:"query" json:"query"`
}

// UsesRego reports whether the profile selects the Rego authority engine.
func (p *Profile) UsesRego() bool { return p.PolicyEngine == "rego" }

// PolicyBundle references a signed policy bundle stored as an OCI artifact.
// When VerifyKey is set the ed25519 signature is verified before the policy
// is loaded.
type PolicyBundle struct {
	Ref       string `toml:"ref" json:"ref"`               // oci://registry/repo:tag or repo@sha256:...
	VerifyKey string `toml:"verify_key" json:"verify_key"` // base64 ed25519 public key; signature verification requires this
	PlainHTTP bool   `toml:"plain_http" json:"plain_http"` // allow http registries (local testing)
	// Insecure explicitly accepts an unsigned/unverified bundle. Without it,
	// a bundle with no verify_key is rejected (fail-closed) rather than trusted.
	Insecure bool `toml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// UsesPolicyBundle reports whether the profile sources its policy from an OCI
// policy bundle.
func (p *Profile) UsesPolicyBundle() bool { return p.PolicyBundle != nil && p.PolicyBundle.Ref != "" }

// Limits declares the cost and loop guardrails for a session. Zero/empty
// values mean unlimited (subject to the backend's secure-by-default ceilings).
type Limits struct {
	// WallClock is a duration string, e.g. "30m".
	WallClock string `toml:"wall_clock" json:"wall_clock"`
	MaxExecs  int    `toml:"max_execs" json:"max_execs"`
	// Memory caps container memory, e.g. "512m" or "2g" (empty = backend default).
	Memory string `toml:"memory" json:"memory"`
	// CPUs caps CPU cores, e.g. 1.5 (zero = backend default).
	CPUs float64 `toml:"cpus" json:"cpus"`
	// EgressRequests caps outbound requests through the proxy.
	EgressRequests int `toml:"egress_requests" json:"egress_requests"`
	// LoopWindow/LoopThreshold kill a session that repeats >= LoopThreshold
	// near-identical failing actions within LoopWindow.
	LoopWindow    string `toml:"loop_window" json:"loop_window"`
	LoopThreshold int    `toml:"loop_threshold" json:"loop_threshold"`
	// MaxTokens caps the cumulative model tokens a sandbox may spend (as
	// reported via the usage API). Zero means unlimited. Once exceeded, further
	// governed tool calls are denied.
	MaxTokens int64 `toml:"max_tokens" json:"max_tokens"`
	// MaxCostUSD caps cumulative reported spend in US dollars. Zero means
	// unlimited. Once exceeded, further governed tool calls are denied.
	MaxCostUSD float64 `toml:"max_cost_usd" json:"max_cost_usd"`
}

// Fleet spawns N sandboxes from the same contract sharing a task board and
// artifact volume.
type Fleet struct {
	Replicas int `toml:"replicas" json:"replicas"`
	// TaskBoard optionally seeds task identifiers to distribute.
	TaskBoard []string `toml:"task_board" json:"task_board"`
}

// Audit configures the tamper-evident ledger sink and redaction policy.
type Audit struct {
	// Sink is a path or URI for the append-only ledger.
	Sink string `toml:"sink" json:"sink"`
	// Redact stores hashes instead of sensitive payloads. Defaults to true.
	Redact *bool `toml:"redact" json:"redact"`
	// ScrubPatterns appends operator-defined regexes to built-in secret scrubbing.
	ScrubPatterns []string `toml:"scrub_patterns" json:"scrub_patterns"`
}

// RedactEnabled reports the effective redaction setting (defaults to true).
func (a Audit) RedactEnabled() bool { return a.Redact == nil || *a.Redact }
