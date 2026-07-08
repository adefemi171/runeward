# REST API

`runeward serve` exposes the control plane over HTTP (default `127.0.0.1:8080`).
All actions flow through the same governed path as every other surface.

## Authentication

`serve` binds `127.0.0.1` by default and refuses a non-loopback `--bind` unless
authentication is configured. Set a bearer token with `--token` /
`RUNEWARD_API_TOKEN`, or point `RUNEWARD_AUTHZ_FILE` at a JSON store of named
principals (each with its own token, an allowed-profile glob list, and
approval/admin flags) for multi-principal RBAC. When set, the token is required
on every request except `/healthz` and the static dashboard shell — pass it as
`Authorization: Bearer <token>`, an `X-Runeward-Token` header, or a `?token=`
query param (the last is required for the terminal WebSocket). Optional TLS via
`--tls-cert`/`--tls-key`; request bodies are capped at 16 MiB. See the
[Security model](security-model.md).

Under RBAC, a non-admin principal sees and can act on only the sandboxes it
created; admins see all.

## Health & identity

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness probe (unauthenticated). |
| `GET` | `/v1/whoami` | The authenticated caller's identity and capabilities (name, admin, can_approve, allowed_profiles). |
| `GET` | `/metrics` | Prometheus metrics. |

## Profiles

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/profiles` | List reachable profiles. |

## Sandboxes

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/sandboxes` | Create a sandbox. Body: `{"profile":"...","copy_from":"..."}` (`copy_from` optional). |
| `GET` | `/v1/sandboxes` | List sandboxes (scoped to the caller under RBAC). |
| `GET` | `/v1/sandboxes/{id}` | Get one sandbox (includes `owner` and cumulative `usage`). |
| `DELETE` | `/v1/sandboxes/{id}` | Kill and remove a sandbox. |

### Actions (governed)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/sandboxes/{id}/shell/exec` | Run a shell command. |
| `POST` | `/v1/sandboxes/{id}/code/python` | Run Python. |
| `POST` | `/v1/sandboxes/{id}/code/node` | Run Node. |
| `POST` | `/v1/sandboxes/{id}/file/read` | Read a file. |
| `POST` | `/v1/sandboxes/{id}/file/write` | Write a file. |
| `POST` | `/v1/sandboxes/{id}/file/list` | List files. |
| `POST` | `/v1/sandboxes/{id}/file/search` | Search files. |
| `POST` | `/v1/sandboxes/{id}/usage` | Report model usage. Body: `{"tokens":123,"cost_usd":0.04}`; accrues toward the profile's `limits.max_tokens`/`max_cost_usd` budget. |
| `GET` | `/v1/sandboxes/{id}/terminal` | WebSocket terminal (same-origin only). |

### Browser

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/sandboxes/{id}/browser` | One-shot browser action. |
| `POST` | `/v1/sandboxes/{id}/browser/sessions` | Open a stateful session. |
| `POST` | `/v1/sandboxes/{id}/browser/sessions/{sid}/act` | Act in a session. |
| `DELETE` | `/v1/sandboxes/{id}/browser/sessions/{sid}` | Close a session. |

## Fleets

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/fleets` | Create a fleet. |
| `GET` | `/v1/fleets` | List fleets. |
| `GET` | `/v1/fleets/{id}` | Get a fleet. |
| `DELETE` | `/v1/fleets/{id}` | Tear down a fleet. |
| `GET` | `/v1/fleets/{id}/tasks` | List tasks. |
| `POST` | `/v1/fleets/{id}/tasks` | Add a task. |
| `POST` | `/v1/fleets/{id}/claim` | Claim the next task (lease). |
| `POST` | `/v1/fleets/{id}/tasks/{taskID}/complete` | Mark complete. |
| `POST` | `/v1/fleets/{id}/tasks/{taskID}/fail` | Mark failed. |
| `POST` | `/v1/fleets/{id}/tasks/{taskID}/heartbeat` | Renew the lease. |

## Snapshots

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/sandboxes/{id}/snapshot` | Snapshot a workspace. |
| `GET` | `/v1/snapshots` | List snapshots. |
| `POST` | `/v1/snapshots/{id}/restore` | Restore a snapshot. |

## Audit

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/sandboxes/{id}/audit` | Audit events for a sandbox. |
| `GET` | `/v1/audit/verify` | Verify the on-disk hash chain. |
| `GET` | `/v1/audit/pubkey` | The ledger's ed25519 public key. |
| `GET` | `/v1/audit/export` | Export a signed transcript bundle. |

## Approvals

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/approvals` | Pending approvals. |
| `POST` | `/v1/approvals/{id}/approve` | Approve a paused action. |
| `POST` | `/v1/approvals/{id}/deny` | Deny a paused action. |

## Example

```bash
AUTH=(-H "Authorization: Bearer $RUNEWARD_API_TOKEN")   # omit when serving without a token: AUTH=()
SB=$(curl -s "${AUTH[@]}" -X POST localhost:8080/v1/sandboxes -d '{"profile":"ns-auto"}' | jq -r .id)
curl -s "${AUTH[@]}" -X POST "localhost:8080/v1/sandboxes/$SB/shell/exec" -d '{"command":["echo","hi"]}'
curl -s "${AUTH[@]}" -X POST "localhost:8080/v1/sandboxes/$SB/usage" -d '{"tokens":1200,"cost_usd":0.03}'
curl -s "${AUTH[@]}" "localhost:8080/v1/audit/verify"
curl -s "${AUTH[@]}" -X DELETE "localhost:8080/v1/sandboxes/$SB"
```
