<p align="center">
  <img src="docs/assets/runeward-banner.png" alt="runeward" width="720" />
</p>

<p align="center">
  <b>Governed execution cells for AI agents.</b>
</p>

<p align="center">
  Declarative profiles provision isolated sandboxes (Docker or Kubernetes) with deny-by-default
  egress, a tamper-evident audit ledger, human-in-the-loop policy gates, and cost/loop guardrails,
  driven over REST, MCP, a CLI, and a web dashboard.
</p>

## Why runeward

Letting an AI agent run shell commands, edit files, install packages, and hit the network is useful
right up until it `rm -rf`s the wrong directory, exfiltrates a secret, or burns your API budget in a
retry loop. Raw isolation ("jail the agent in a box") is table stakes. runeward adds the governance
layer *around* the box that most sandboxes lack. Think of it as a seatbelt and flight recorder for
autonomous agents.

- **Profiles are a security contract.** `[host]`, `[network]`, `[[env]]`, `[[file]]`, `[[policy]]`,
  and `[limits]` declare exactly the access a task needs. Everything you didn't grant is denied by
  default, so the blast radius is explicit.
- **Governed, not just isolated.** Every action flows through one path (policy, approval gate,
  guardrails, backend exec, audit ledger) whether it arrives via REST, the dashboard, or MCP.
- **Tamper-evident by construction.** An append-only, hash-chained, ed25519-signed ledger records
  every call and its verdict, and exports as an independently verifiable transcript.
- **Human-in-the-loop where it matters.** Per-action `allow` / `deny` / `require-approval` verdicts
  pause risky operations for an operator instead of guessing.
- **Cost and loop guardrails.** Hard caps on wall-clock, exec count, and egress requests, plus
  retry-loop detection, stop runaway agents.
- **Pluggable backends.** A Docker/Podman backend for zero-setup laptop use, or a Kubernetes backend
  (with strict L3 egress, CRDs, and an admission webhook) for production and fleets. Everything above
  the backend is identical.
- **Isolated workspaces from your real code.** `copy_from` seeds a sandbox with a copy of a local
  folder (never a mount), and `runeward export` pulls results back out, so the agent works on your
  project without ever touching the original.

### How it compares

|                                    | typical agent sandbox | runeward                                     |
| ---------------------------------- | --------------------- | -------------------------------------------- |
| Isolation (container/VM)           | yes                   | yes (Docker or Kubernetes)                   |
| Deny-by-default network egress     | sometimes             | yes; SNI allowlist, strict L3 on k8s         |
| Per-action policy + approvals      | rare                  | yes; builtin / CEL / OPA-Rego + HITL gates   |
| Tamper-evident, signed audit trail | rare                  | yes; hash-chained + ed25519, verifiable      |
| Cost / loop guardrails             | rare                  | yes; wall-clock, exec, egress, loop caps     |
| Multi-agent fleets                 | rare                  | yes; N cells + atomic task board             |
| Agent-native surface               | partial               | REST + MCP + CLI + dashboard + SKILL/adapters|

## How runeward fits your agent stack

There are two ways to put an agent behind runeward:

1. **As an MCP server for your IDE/agent (Cursor, Claude Desktop, VS Code).** Point the tool at
   `runeward mcp`; its agent then runs shell/code/file/browser tools inside a governed sandbox
   instead of on your host. Isolation, policy, egress, and audit apply to everything it does.
2. **By running an agent CLI inside the sandbox (Codex, Cursor CLI).** A profile ships the agent
   binary in the image and injects its API key; you launch the agent with a single governed exec call
   (or a whole fleet of them). See [Running agents and fleets](#running-agents-and-fleets).

## Quick start

```bash
# Build the single binary
go build -o bin/runeward ./cmd/runeward

# Inspect a profile's resolved, secret-redacted policy before using it
./bin/runeward --config-dir examples print ns-auto

# List reachable profiles
./bin/runeward --config-dir examples list

# Step into a sandbox interactively (needs Docker/OrbStack running)
./bin/runeward --config-dir examples dev

# Run a single command in a fresh sandbox, then tear it down
./bin/runeward --config-dir examples dev -- uname -a

# Start the governed control plane (REST API + web dashboard) on :8080
./bin/runeward --config-dir examples serve
```

Open [http://localhost:8080](http://localhost:8080) for the dashboard: pick a profile, click **New**
(optionally point it at a local folder to copy in), and drive the sandbox's terminal, files, shell,
audit timeline, and approvals inbox.

## Working against your own code

runeward never mounts your host folder into the sandbox. Instead it takes a one-time copy at create,
so the agent works on an isolated `/workspace` and your real files are never modified. There are
three ways to seed it.

**1. In a profile** with `host.copy_from`:

```toml
[host]
type      = "container"
image     = "runeward-agent:dev"
workdir   = "/workspace"
copy_from = "~/Documents/my-project"   # contents copied into /workspace at create
```

**2. Per-create over REST or the dashboard**, overriding it for a single sandbox:

```bash
curl -sX POST localhost:8080/v1/sandboxes \
  -d '{"profile":"codex-agent","copy_from":"~/Documents/my-project"}'
```

The dashboard's New dialog has an optional "Copy local folder into workspace" field.

**3. Pull results back out** to a host directory (the sandbox is only read; later host edits never
flow back in):

```bash
./bin/runeward export <sandbox-id> ./agent-output      # works for Docker and Kubernetes cells
```

Snapshots (`POST /v1/sandboxes/{id}/snapshot`) are the other way to preserve or fork a workspace.

## Running agents and fleets

Build the agent image once (it ships `codex`, the Cursor CLI, git, python, node, and `tar`):

```bash
docker build -f deploy/Dockerfile.agent -t runeward-agent:dev .
```

### Codex (OpenAI)

```bash
printf '%s' "$OPENAI_API_KEY" > ~/.runeward-openai.key   # key read at launch, redacted from ledger
./bin/runeward --config-dir examples serve

# create the governed cell, then run the agent inside it
SB=$(curl -sX POST localhost:8080/v1/sandboxes -d '{"profile":"codex-agent"}' | jq -r .id)
curl -sX POST localhost:8080/v1/sandboxes/$SB/shell/exec -d '{"command":["sh","-lc",
  "codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox '\''write fib.py and run it'\''"]}'
```

`--dangerously-bypass-approvals-and-sandbox` is correct here: runeward is the external sandbox.
`codex exec` authenticates from `CODEX_API_KEY`, so [examples/codex-agent.toml](examples/codex-agent.toml)
injects both `CODEX_API_KEY` and `OPENAI_API_KEY` from the same key file. Only `api.openai.com` is
reachable; everything else is denied.

### Cursor CLI

```bash
printf '%s' "$CURSOR_API_KEY" > ~/.runeward-cursor.key
SB=$(curl -sX POST localhost:8080/v1/sandboxes -d '{"profile":"cursor-agent"}' | jq -r .id)
curl -sX POST localhost:8080/v1/sandboxes/$SB/shell/exec -d '{"command":["sh","-lc",
  "agent -p '\''write fib.py and run it'\'' --force --trust --output-format text"]}'
```

See [examples/cursor-agent.toml](examples/cursor-agent.toml). The Cursor CLI is Node-based, so the
profile sets `NODE_USE_ENV_PROXY=1` to route it through runeward's cooperative Docker egress proxy;
only Cursor's endpoints are allowed.

### Claude / Cursor / VS Code (via MCP)

For IDE agents, expose runeward's governed tools over MCP and let the IDE drive sandboxes:

```jsonc
// e.g. Cursor .cursor/mcp.json or Claude Desktop config
{ "mcpServers": { "runeward": { "command": "runeward", "args": ["mcp", "--config-dir", "examples"] } } }
```

The agent then calls `runeward_create_sandbox` (which accepts an optional `copy_from`),
`runeward_shell`, `runeward_python`, `runeward_read_file`, `runeward_browser_*`, and so on, all
governed.

### Fleets (many agents, one task board)

A fleet is N identical governed cells sharing an atomic, concurrency-safe task board. Set the replica
count and per-agent model/prompt in the profile ([examples/codex-fleet.toml](examples/codex-fleet.toml),
[examples/cursor-fleet.toml](examples/cursor-fleet.toml)):

```toml
[fleet]
replicas = 3
```

```bash
FL=$(curl -sX POST localhost:8080/v1/fleets -d '{"profile":"codex-fleet"}' | jq -r .id)
curl -sX POST localhost:8080/v1/fleets/$FL/tasks  -d '{"payload":"refactor module A"}'
curl -sX POST localhost:8080/v1/fleets/$FL/claim  -d '{"owner":"w1"}'   # atomic claim by a worker
```

Dead workers' claims auto-requeue via leases, and the board survives restarts. Pin the model per
agent by baking it into the profile's launch command (e.g. `codex exec -m o3` or `agent --model ...`).

**Coordination model.** Agents do not talk to each other directly. Each sandbox is isolated (its own
container/pod, workspace, and deny-by-default egress), so one agent cannot reach another unless you
explicitly allowlist it. Instead, workers in a fleet coordinate through the shared task board via the
control plane (claim / complete / fail), which keeps every interaction atomic and audited. Separate
fleets each have their own board and are fully isolated from one another.

## Profiles

Profiles may be authored in TOML, YAML, or JSON; the file extension picks the parser and all three
share the same schema (TOML is shown throughout these docs). `runeward <name>` resolves
`<name>.{toml,yaml,yml,json}` in order:

1. `./.runeward/<name>.*`, project-local and committed with the repo.
2. `~/.config/runeward/<name>.*` (or `$XDG_CONFIG_HOME/runeward/`).

`--config-dir DIR` (or `$RUNEWARD_CONFIG_DIR`) pins the search to a single directory, used for the
sanitized templates in [examples/](examples/). See [examples/ns-auto.toml](examples/ns-auto.toml) for
a fully worked deny-by-default profile.

Secrets in `[[env]]` are resolved fresh at launch (`value`, `file`, or `op` for 1Password), injected
into the session, redacted from the ledger, and never written under `$HOME`.

## CLI

```
runeward <profile> [-- cmd...]       Provision a sandbox for a profile and enter it (alias for enter)
runeward enter <profile>             Same, explicit; --keep leaves the sandbox running
runeward export <id> <dir>           Copy a sandbox's /workspace back out to a host directory
runeward print <profile>             Show the resolved, secret-redacted profile + policy
runeward list                        List reachable profiles
runeward serve                       Governed control plane: REST API + web dashboard (:8080)
runeward mcp [--http]                Model Context Protocol server (stdio, or streamable HTTP)
runeward up [--crds-only]            Install CRDs + namespace + RBAC + controller into k8s
runeward controller                  Reconcile Sandbox/Fleet CRDs onto the k8s backend
runeward webhook                     Self-registering admission webhook for ClusterPolicy
runeward audit verify                Verify the hash chain + signatures of the ledger
runeward bundle {keygen,push,pull}   Build/publish/verify signed OCI policy bundles
```

## Control plane (REST)

`runeward serve` routes every tool call through policy, approval gate, guardrails, backend exec, and
the audit ledger, whether it arrives over REST, the dashboard, or MCP.

```
GET      /healthz
GET      /v1/profiles
POST     /v1/sandboxes                      {"profile":"dev","copy_from":"~/proj"}   # copy_from optional
GET      /v1/sandboxes   ·  GET|DELETE /v1/sandboxes/{id}
POST     /v1/sandboxes/{id}/shell/exec      {"command":["ls","-la"]}
POST     /v1/sandboxes/{id}/code/python     {"code":"print(2+2)"}
POST     /v1/sandboxes/{id}/code/node       {"code":"..."}
POST     /v1/sandboxes/{id}/file/{read,write,list,search}
POST     /v1/sandboxes/{id}/snapshot        {"name":"before-refactor"}
GET      /v1/snapshots   ·  POST /v1/snapshots/{id}/restore
POST     /v1/fleets                         {"profile":"fleet-demo"}   # N cells + shared task board
GET      /v1/fleets   ·  GET|DELETE /v1/fleets/{id}
GET|POST /v1/fleets/{id}/tasks             # list / add tasks
POST     /v1/fleets/{id}/claim             {"owner":"w1"}             # atomic claim
POST     /v1/fleets/{id}/tasks/{tid}/{complete,fail}
GET      /v1/sandboxes/{id}/audit          # this sandbox's ledger events
GET      /v1/sandboxes/{id}/terminal       # interactive PTY over WebSocket
GET      /v1/audit/verify                  # verify the hash chain + signatures
GET      /v1/approvals   ·  POST /v1/approvals/{id}/{approve,deny}
POST     /mcp                              # Model Context Protocol (streamable HTTP)
```

A denied tool call returns `403`; a require-approval call blocks until an operator resolves it via
the approvals inbox (returning `202` with an `approval_id` if it waits too long). Pin the ledger and
signing-key location with `$RUNEWARD_STATE_DIR`.

## MCP

`runeward mcp` exposes the same governed tools over the Model Context Protocol: stdio by default
(Claude Desktop / Cursor / VS Code), or `--http` for the streamable transport (also mounted at `/mcp`
by `runeward serve`).

- **Sandbox tools:** `runeward_create_sandbox` (accepts `copy_from`), `runeward_shell`,
  `runeward_browser`, `runeward_browser_open`, `runeward_browser_act`, `runeward_browser_close`,
  `runeward_python`, `runeward_node`, `runeward_read_file`, `runeward_write_file`,
  `runeward_list_files`, `runeward_search_files`, `runeward_list_approvals`, `runeward_kill_sandbox`.
- **Fleet tools:** `runeward_create_fleet`, `runeward_list_fleets`, `runeward_list_tasks`,
  `runeward_add_task`, `runeward_claim_task`, `runeward_complete_task`, `runeward_fail_task`,
  `runeward_kill_fleet`.

A policy deny surfaces as a tool error; a require-approval verdict tells the agent to pause for a human.

## Kubernetes

One command installs the CRDs and the controller into the current cluster (idempotent, server-side
apply, using your kubeconfig):

```bash
go build -o bin/runeward ./cmd/runeward
docker build -f deploy/Dockerfile -t runeward:latest .   # shared with OrbStack/Docker Desktop k8s
./bin/runeward up                                         # CRDs + namespace + RBAC + controller
# or just the CRDs:  ./bin/runeward up --crds-only

# Provide profiles the controller can resolve
kubectl -n runeward create configmap runeward-profiles --from-file=examples/
```

Or via Helm:

```bash
helm install runeward deploy/helm/runeward -n runeward --create-namespace \
  --set image.tag=latest --set server.enabled=true
```

Then drive it declaratively:

```yaml
apiVersion: runeward.dev/v1alpha1
kind: Sandbox
metadata: { name: demo, namespace: runeward }
spec: { profile: k8s }
---
apiVersion: runeward.dev/v1alpha1
kind: Fleet
metadata: { name: crew, namespace: runeward }
spec: { profile: fleet-demo }
```

```bash
kubectl -n runeward get sandboxes,fleets
```

The controller provisions the backing Pods/PVCs, populates `.status` (`sandboxId`/`fleetId`, phase,
task stats), and tears everything down via a finalizer on delete. On k8s, egress can be enforced at
L3 (`enforce = "strict"`: an iptables init container plus a transparent SNI proxy) so it cannot be
bypassed by an uncooperative process.

For org-shared cells that shouldn't live in a single team's namespace, use cluster-scoped
`ClusterSandbox` / `ClusterFleet` (same spec, no `namespace`); the same controller reconciles them
cluster-wide.

### Org-wide policy defaults

A cluster-scoped `ClusterPolicy` sets org-wide guardrails on `Sandbox`/`Fleet` resources, enforced by
`runeward webhook` (a self-registering validating and mutating admission webhook that mints its own
serving cert):

```yaml
apiVersion: runeward.dev/v1alpha1
kind: ClusterPolicy
metadata: { name: org-defaults }
spec:
  allowedProfiles: ["k8s", "fleet-*"]   # globs; empty = any
  deniedProfiles: ["*-admin"]
  defaultProfile: "k8s"                  # mutating: fills empty spec.profile
  allowedNamespaces: ["team-*"]
  requiredLabels: ["owner"]
```

Enable it with the chart (`--set webhook.enabled=true`); the webhook admits by default (fail-open)
and denies only resources that violate a policy.

## Policy engines

Authority is `allow` / `deny` / `require-approval` per action, chosen with `policy_engine`:

- `builtin` (default): first-match tool + glob rules (`[[policy]]`).
- `cel`: CEL expressions over `{tool, arg}` (`[[cel]]`); see `examples/`.
- `rego`: OPA/Rego module returning `data.runeward.decision` (`[rego]`); see
  [examples/rego.toml](examples/rego.toml).

Instead of embedding policy inline, a profile can pull it from a signed, versioned OCI policy bundle,
so a security team ships one artifact many profiles consume:

```toml
[policy_bundle]
ref        = "oci://ghcr.io/acme/runeward-policies:v3"
verify_key = "<base64 ed25519 public key>"   # when set, a valid signature is REQUIRED (fail-closed)
```

```bash
runeward bundle keygen --out ./keys
runeward bundle push oci://ghcr.io/acme/runeward-policies:v3 \
    --policy prod.rego --engine rego --key ./keys/bundle.key
runeward bundle pull oci://ghcr.io/acme/runeward-policies:v3 --verify-key ./keys/bundle.pub
```

The signature covers the content-addressed config and layer digests and rides in the OCI manifest
annotations; see [examples/policy-bundle.toml](examples/policy-bundle.toml).

## Testing

See [docs/E2E-TESTING.md](docs/E2E-TESTING.md) for an end-to-end local walkthrough covering the Docker
and Kubernetes backends, deny-by-default and strict egress, snapshots, multi-agent fleets, and wiring
the MCP server into Claude Desktop, Cursor, and VS Code.

## License

TBD.
