<p align="center">
  <img src="docs/assets/runeward-banner.png" alt="runeward" width="720" />
</p>

<p align="center">
  <b>Governed execution cells for AI agents.</b>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://github.com/Runewardd/runeward/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Runewardd/runeward/actions/workflows/ci.yml/badge.svg"></a>
  <a href="go.mod"><img alt="Go" src="https://img.shields.io/badge/go-1.25%2B-00ADD8.svg"></a>
  <a href="https://github.com/Runewardd/runeward/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Runewardd/runeward?sort=semver"></a>
</p>

<p align="center">
  Declarative Charters provision isolated Citadels (Docker or Kubernetes) with a deny-by-default
  Perimeter, a tamper-evident Chronicle, human-in-the-loop policy gates, and cost/loop Rationing,
  driven over REST, MCP, a CLI, and a web dashboard.
</p>

## Why runeward

Letting an AI agent run shell commands, edit files, and hit the network is useful right up until it
`rm -rf`s the wrong directory, exfiltrates a secret, or burns your budget in a retry loop. Isolation
alone is table stakes; runeward adds the **governance layer around the box** — a deny-by-default
contract the agent can't talk its way past, enforced outside the model. See
[Why governance, not training](https://runewardd.github.io/runeward/why-governance/).

- **Charters are a security contract.** `[host]`, `[network]`, `[[env]]`, `[[policy]]`, `[rationing]`
  declare exactly the access a task needs; everything else is denied by default.
- **Governed, not just isolated.** Every action flows through one path — policy → Conclave gate →
  Rationing → backend exec → Chronicle — whether it arrives via REST, the dashboard, or MCP.
- **Tamper-evident.** An append-only, hash-chained, ed25519-signed Chronicle records every call and
  verdict and exports as an independently verifiable transcript.
- **Human-in-the-loop.** Per-action `allow` / `deny` / `require-approval` verdicts pause risky work.
- **Cost & loop Rationing.** Hard caps on wall-clock, exec count, egress, and token/spend budgets.
- **Authenticated & multi-user.** Loopback by default; bearer token + optional per-principal RBAC.
- **Pluggable backends.** Docker/Podman for laptops, Kubernetes (strict L3 egress, CRDs, admission
  webhook, PSA + NetworkPolicy) for production and Cohorts. Everything above the backend is identical.

|                                    | typical agent sandbox | runeward                                     |
| ---------------------------------- | --------------------- | -------------------------------------------- |
| Isolation (container/VM)           | yes                   | yes (Docker or Kubernetes)                   |
| Deny-by-default network egress     | sometimes             | yes; SNI allowlist, strict L3 on k8s         |
| Per-action policy + approvals      | rare                  | yes; builtin / CEL / OPA-Rego + HITL gates   |
| Tamper-evident, signed audit trail | rare                  | yes; hash-chained + ed25519, verifiable      |
| Cost / loop guardrails             | rare                  | yes; wall-clock, exec, egress, token/spend   |
| Multi-agent Cohorts                | rare                  | yes; N cells + atomic Command Board          |
| Control-plane auth + multi-user    | rare                  | yes; bearer token + RBAC + per-user views    |
| Agent-native surface               | partial               | REST + MCP + CLI + dashboard + SKILL/adapters|

## Vocabulary

runeward uses a desert-governance vocabulary consistently across the CLI, REST, MCP, CRDs, and
Charter files: a **Citadel** (sandbox), a **Cohort** (fleet), a **Charter** (profile), the
**Conclave** (approvals), the **Chronicle** (audit ledger), the **Perimeter** (egress), and
**Rationing** (guardrails). The `runeward` binary name, SDK method names, and JSON body fields (e.g.
`profile`) keep their original spellings. Full glossary: [Concepts](docs/concepts.md#product-vocabulary).

## Quick start

```bash
# Install (macOS/Linux/Windows CLI, amd64/arm64)
curl -fsSL https://raw.githubusercontent.com/Runewardd/runeward/main/install.sh | sh
# or: brew install Runewardd/tap/runeward   # once the tap is published
# or build from source: go build -o bin/runeward ./cmd/runeward
```

```bash
runeward --config-dir examples list                 # list reachable Charters
runeward --config-dir examples print ns-auto        # inspect a resolved, secret-redacted Charter
runeward --config-dir examples dev -- uname -a       # run one command in a fresh Citadel (needs Docker)
runeward --config-dir examples serve                # governed REST API + dashboard on :8080
```

Open [localhost:8080](http://localhost:8080): pick a Charter, click **New**, and drive the Citadel's
terminal, files, Chronicle timeline, and Conclave inbox. Full walkthrough:
[Quickstart](https://runewardd.github.io/runeward/quickstart/).

## Integrating an agent

Two ways to put an agent behind runeward:

- **As an MCP server for your IDE** (Cursor, Claude Desktop, VS Code) — point the tool at
  `runeward mcp`; its agent runs shell/code/file/browser tools inside a governed Citadel:

  ```jsonc
  { "mcpServers": { "runeward": { "command": "runeward", "args": ["mcp", "--config-dir", "examples"] } } }
  ```

- **By running an agent CLI inside a Citadel** (Codex, Cursor CLI, Claude Code) — a Charter ships the
  agent binary and injects its key; launch one with a governed exec call, or a whole **Cohort**:

  ```bash
  runeward cohort --agent claude --model sonnet build "Build a FastAPI todo API with tests"
  ```

A Cohort is N identical governed cells sharing an atomic Command Board (`[cohort] replicas = N`). Use
`exec` to iterate on one workspace, or `add` + `run` to fan independent tasks out in parallel.
runeward governs whatever command you exec, so cloud CLIs and local LLMs both work. Details:
[Cohorts & agents](https://runewardd.github.io/runeward/fleets/).

## Working against your own code

runeward never mounts your host folder — it takes a one-time copy at create, so the agent works on an
isolated `/workspace` and your real files are untouched. Seed it via `host.copy_from` in a Charter,
`copy_from` per-create over REST/dashboard, or snapshots; pull results back with
`runeward export <citadel-id> ./out`.

## CLI

```
runeward <charter> [-- cmd...]       Provision a Citadel for a Charter and enter it (alias for enter)
runeward enter <charter>             Same, explicit; --keep leaves the Citadel running
runeward cohort <up|add|run|build|exec|status|export|down>   Drive a prompt-driven Cohort (--agent/--model)
runeward export <id> <dir>           Copy a Citadel's /workspace back out to a host directory
runeward print <charter>             Show the resolved, secret-redacted Charter + policy
runeward list                        List reachable Charters
runeward validate <charter>          Statically lint a Charter (missing images, unresolved secrets, dead rules)
runeward policy {test,scaffold}      Simulate a Charter's policy, or print a ready-made policy template
runeward charter {sign,verify}       Produce/verify a detached ed25519 signature over a Charter
runeward runtime {check,guide,install}  Inspect, explain, or install hardened runtimes (gVisor/Kata)
runeward replay <cast>               Replay a recorded terminal session (asciinema v2)
runeward serve [--token ...]         Governed control plane: REST API + web dashboard (127.0.0.1:8080)
runeward mcp [--http]                Model Context Protocol server (stdio, or streamable HTTP)
runeward up [--crds-only]            Install CRDs + namespace + RBAC + controller into k8s
runeward controller                  Reconcile Citadel/Cohort CRDs onto the k8s backend
runeward webhook                     Self-registering admission webhook for ClusterPolicy
runeward chronicle verify            Verify the hash chain + signatures of the Chronicle
runeward archive {keygen,push,pull}  Build/publish/verify signed OCI policy Archives
```

## Interfaces

- **REST** — `runeward serve` routes every call through the governed path over `/v1/citadels`,
  `/v1/cohorts`, `/v1/conclave`, `/v1/chronicle`, and more. Loopback by default; set `--token` /
  `$RUNEWARD_API_TOKEN` (or RBAC via `$RUNEWARD_AUTHZ_FILE`) before exposing it. A deny returns `403`;
  require-approval blocks until resolved. Reference: [REST API](https://runewardd.github.io/runeward/rest-api/).
- **MCP** — the same tools over the Model Context Protocol (`runeward_create_citadel`,
  `runeward_shell`, `runeward_create_cohort`, …), stdio or streamable HTTP.
- **Adapters** — first-class tools for LangChain, CrewAI, LlamaIndex, OpenAI Agents, Strands, and the
  Vercel AI SDK via `pip install runeward` / `npm install @runeward/sdk`. See
  [Adapters](https://runewardd.github.io/runeward/adapters/) and [`adapters/`](adapters/).
- **Observability** — Prometheus metrics at `/metrics`, structured `log/slog` logs, opt-in telemetry.
  See [Observability](https://runewardd.github.io/runeward/observability/).

## Kubernetes

```bash
./bin/runeward up                                        # CRDs + namespace + RBAC + controller
kubectl -n runeward create configmap runeward-profiles --from-file=examples/
# or: helm install runeward deploy/helm/runeward -n runeward --create-namespace --set server.enabled=true
```

Then drive it declaratively with `Citadel` / `Cohort` (or cluster-scoped `ClusterCitadel` /
`ClusterCohort`) resources; the controller provisions Pods/PVCs and tears them down via finalizers.
Org-wide guardrails come from a `ClusterPolicy` enforced by `runeward webhook`, and strict L3 egress,
PSA, NetworkPolicy, and hardened runtimes (gVisor/Kata) harden multi-tenant clusters. Details:
[Security model](https://runewardd.github.io/runeward/security-model/).

## Policy engines

Authority is `allow` / `deny` / `require-approval` per action, chosen with `policy_engine`: `builtin`
(glob rules), `cel` (CEL over `{tool, arg}`), or `rego` (OPA/Rego). A Charter can also pull a signed,
versioned OCI policy Archive so a security team ships one artifact many Charters consume:

```bash
runeward archive push oci://ghcr.io/acme/runeward-policies:v3 --policy prod.rego --engine rego --key ./keys/bundle.key
```

See [Charters & policy](https://runewardd.github.io/runeward/profiles/) and [examples/](examples/).

## Docs & testing

Full documentation: **[runewardd.github.io/runeward](https://runewardd.github.io/runeward/)**. For an
end-to-end local walkthrough (both backends, strict egress, snapshots, Cohorts, MCP wiring), see
[docs/E2E-TESTING.md](docs/E2E-TESTING.md).

## Contributing & license

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Found a security issue? Follow [SECURITY.md](SECURITY.md) and
report it privately. Licensed under [Apache 2.0](LICENSE); see [NOTICE](NOTICE) for attribution.
