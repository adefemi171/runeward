# Security model

runeward's job is to reduce the blast radius of an autonomous agent. Knowing what
it does — and does not — protect against is essential to using it safely.

For **reporting vulnerabilities**, see
[SECURITY.md](https://github.com/Runewardd/runeward/blob/main/SECURITY.md).
Please disclose privately; do not open a public issue.

## What runeward provides

- **Isolation.** Each cell runs in a container (Docker/Podman) or Pod (Kubernetes)
  with its own workspace. Docker cells are hardened by default: all Linux
  capabilities dropped, `no-new-privileges`, a `--pids-limit`, and default
  memory/CPU ceilings (overridable via `RUNEWARD_SANDBOX_MEMORY`,
  `RUNEWARD_SANDBOX_CPUS`, `RUNEWARD_SANDBOX_PIDS`; set to `0` to disable).
  Setting `host.read_only = true` mounts the root filesystem read-only (with a
  writable `/tmp` and the writable workspace) on both Docker and Kubernetes.
  `host.seccomp` / `host.apparmor` pin a seccomp/AppArmor profile (Docker
  `--security-opt`; Kubernetes Localhost profiles), and Kubernetes pods default
  to the runtime's seccomp profile rather than Unconfined.
- **Control-plane authentication.** `runeward serve` binds `127.0.0.1` by
  default and refuses any non-loopback `--bind` unless authentication is set (an
  API token via `--token` / `RUNEWARD_API_TOKEN`, or an RBAC store). When set it
  is required on every request — REST, `/mcp`, the terminal WebSocket, and the
  dashboard — and optional TLS is available via `--tls-cert`/`--tls-key`.
  Request bodies are size-capped to bound memory use.
- **RBAC / multi-principal auth.** Setting `RUNEWARD_AUTHZ_FILE` to a JSON store
  of principals (each with its own token, an allowed-profile glob list, and
  approval/admin flags) upgrades the single shared token to per-principal
  access: the server enforces which profiles a caller may launch and whether it
  may resolve approvals, and records the principal name as the audit actor.
  Each sandbox records its owning principal; a non-admin can see and act on only
  its own sandboxes (an ownership guard enforces this on every
  `/v1/sandboxes/{id}` route), while admins see all. The dashboard has an
  interactive token login (backed by `/v1/whoami`) that gates create/approve
  controls to what the caller is permitted; the static dashboard shell loads
  without a token so the login screen can render, but the API always requires
  one.
- **Cost / token budgets.** Agents or fleet workers report model usage to
  `POST /v1/sandboxes/{id}/usage`; usage accrues per sandbox and per profile
  (surfaced in Prometheus and the sandbox view). A profile's `limits.max_tokens`
  / `limits.max_cost_usd` caps are enforced fail-closed — once exceeded, further
  governed tool calls are denied.
- **Attributed approvals.** Resolving an approval records *who* decided it (the
  RBAC principal name, else `X-Runeward-Actor`, else the peer address) in the
  audit ledger.
- **Deny-by-default egress, enforced at L3 on both backends.** Network access is
  denied unless explicitly allowlisted. Cooperative mode points the sandbox at
  the proxy via `HTTP(S)_PROXY` (the host proxy requires a per-cell credential);
  strict mode (`network.enforce = "strict"`) enforces transparently at the
  kernel: on Kubernetes via an iptables init container + sidecar sharing the pod
  netns, and on Docker via a `NET_ADMIN` egress sidecar that owns the netns
  (the sandbox joins it with `--network container:…`). In strict mode all TCP is
  redirected through the proxy regardless of proxy env, so code that ignores it
  can't bypass the allowlist. The strict path also drops non-DNS UDP (blocking
  QUIC/HTTP3 bypass) and IPv6 egress; setting `RUNEWARD_DNS_RESOLVERS`
  (comma-separated IPs) additionally confines DNS (UDP+TCP :53) to those
  resolvers, closing DNS as a covert exfil channel.
- **Per-action policy and approvals.** `allow` / `deny` / `require-approval`
  verdicts, with human-in-the-loop gates for risky operations.
- **Guardrails.** Hard caps on wall-clock, exec count, egress requests, and
  token/spend budgets, plus retry-loop detection.
- **Tamper-evident audit.** An append-only, hash-chained, ed25519-signed ledger,
  independently verifiable offline. Events can also stream in real time to a
  webhook or file sink (`RUNEWARD_AUDIT_WEBHOOK_URL` / `RUNEWARD_AUDIT_FILE`)
  for SIEM ingestion, over a non-blocking queue that never stalls the ledger. A
  built-in anomaly detector flags novel egress targets, exec bursts, and denial
  spikes (`RUNEWARD_ANOMALY_*`).
- **Terminal session recording.** With `RUNEWARD_RECORD_TERMINALS=1`, governed
  terminal sessions are captured as asciinema v2 casts under the state dir and
  can be replayed with `runeward replay` as part of the audit trail.
- **No host mounts.** `copy_from` copies into the sandbox; the host tree is never
  mounted, so the agent can't reach beyond what you seeded. Set
  `RUNEWARD_COPY_FROM_ROOTS` (a colon-separated allowlist) to confine which host
  directories `copy_from` may read; sources outside the roots fail creation.
- **Kubernetes multi-tenancy.** The managed namespace carries Pod Security
  Admission labels (`RUNEWARD_K8S_PSA_ENFORCE`, or the chart's
  `podSecurityStandard`), sandbox containers always drop `ALL` capabilities and
  disable privilege escalation, and an optional default-deny NetworkPolicy
  (DNS-only egress) isolates sandbox pods (`RUNEWARD_K8S_NETWORK_POLICY`, or the
  chart's `networkPolicy.enabled`) so cells can't reach each other or the control
  plane laterally.
- **Admission enforcement defaults.** The validating ClusterPolicy webhook is
  fail-closed (`failurePolicy: Fail`) so webhook outages block admission for
  governed resources. The mutating default-profile webhook is best-effort
  (`failurePolicy: Ignore`) and only fills missing `spec.profile`.
- **Supply-chain assurance.** Releases are cosign-signed (keyless) with SBOMs,
  and CI runs SAST (gosec, CodeQL), dependency/vuln scanning (govulncheck, Trivy),
  per-image CVE scans, and a DAST baseline, with Dependabot keeping dependencies
  current.

## In scope (please report)

- Sandbox escape from a cell to the host or another cell.
- Bypass of the egress allowlist, policy engine, or approval gates.
- Audit-ledger forgery or silent tampering that verification would miss.
- Path traversal / writes outside the intended workspace (e.g. tar-slip).
- Auth/authorization flaws in the REST API, WebSocket terminal, or admission
  webhook.
- Secret leakage in logs, the ledger, or the dashboard.

## Operator responsibility (out of scope)

- Security of the container runtime, host kernel, and Kubernetes cluster — keep
  them patched.
- Trustworthiness of images referenced by profiles and of the agents/CLIs you run
  inside a cell.
- Secrets you place in profiles; runeward redacts *declared* secret values from
  the ledger and additionally masks common credential shapes (API keys, bearer
  tokens, PEM keys, `password=`/`token=` pairs) wherever they appear, but
  pattern matching is best-effort and can't catch every custom format.
- Network exposure of `runeward serve`. It binds `127.0.0.1` and requires an API
  token before any non-loopback bind, but you still choose the token strength,
  terminate TLS appropriately, and front it with your own proxy/SSO if you need
  richer authn/z than a shared token.
- Denial of service from workloads you explicitly grant large resource limits.

## Operational notes

!!! warning "One writer per ledger"
    The audit ledger is single-writer, protected by a file lock. Give each running
    instance its own `RUNEWARD_STATE_DIR`. Two processes sharing one ledger produce
    out-of-order/duplicate records, permanently breaking the hash chain so
    verification reports tampering.

!!! note "Same-origin WebSocket"
    The dashboard terminal WebSocket enforces a same-origin check to prevent
    cross-site hijacking, and state-changing REST requests reject mismatched
    browser `Origin`s. Set `RUNEWARD_RATE_LIMIT` (requests/sec per client IP) to
    enable per-IP rate limiting. Front the control plane with TLS in production.

runeward is defense-in-depth, not a hard isolation boundary. Its default
container backend shares the host kernel, so a determined escape via a kernel or
runtime vulnerability is possible. For untrusted or adversarial workloads, add
VM-grade isolation by setting `host.runtime_class` in the profile to a
sandboxed runtime. On Kubernetes this maps to `runtimeClassName` (e.g. `gvisor`
or `kata`); on Docker it maps to `docker run --runtime` (e.g. `runsc` for
gVisor, or `kata-runtime`). The runtime must first be installed and registered
with your engine — runeward does not install it, and a name the engine doesn't
recognize fails cell creation rather than silently falling back to the
shared-kernel runtime. `runeward runtime check` probes Docker and Kubernetes for
registered `runsc`/`kata` runtimes and `runeward runtime guide` prints the setup
steps. For the strictest cases, also use a disposable host.
runeward's sweet spot is governing a cooperative-but-fallible agent, not caging
code whose goal is to break out.
