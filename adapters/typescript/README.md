# @runeward/sdk (TypeScript)

A dependency-light TypeScript client and [Vercel AI SDK](https://sdk.vercel.ai)
tool wrappers for the [runeward](https://github.com/Runewardd/runeward)
**governed execution cell** — provision isolated sandboxes and run shell /
Python / Node / file tools through a policy engine, audit ledger, guardrails,
and human-in-the-loop approval gates.

The core `RunewardClient` uses the global `fetch` and has **no runtime
dependencies** (Node 18+, Deno, Bun, browsers). The Vercel AI SDK wrappers
require `ai` and `zod`; the LangChain.js wrappers require `@langchain/core` and
`zod`; the Strands wrappers require `@strands-agents/sdk` and `zod`. All are
optional peer dependencies, imported lazily.

## Install

```bash
npm install @runeward/sdk                           # core client only
npm install @runeward/sdk ai zod                    # + Vercel AI SDK tools
npm install @runeward/sdk @langchain/core zod       # + LangChain.js tools
npm install @runeward/sdk @strands-agents/sdk zod   # + Strands Agents SDK tools
```

Build from this directory during development:

```bash
npm install
npm run build      # emits ./dist
```

## Quick start

Start the control plane first (`runeward serve`, default
`http://localhost:8080`), then:

```ts
import { RunewardClient, RunewardDenied, RunewardApprovalRequired } from "@runeward/sdk";

const rw = new RunewardClient({ baseUrl: "http://localhost:8080" });

const sbx = await rw.createSandbox("dev");
const version = await rw.shell(sbx.id, ["python3", "--version"]);
console.log(version.stdout); // "Python 3.11.2\n"

await rw.writeFile(sbx.id, "/workspace/main.py", "print(2 + 2)");
const run = await rw.python(sbx.id, "exec(open('/workspace/main.py').read())");
console.log(run.stdout); // "4\n"

await rw.killSandbox(sbx.id); // always tear down when done
```

Use `allowInsecure: true` (or `RUNEWARD_ALLOW_INSECURE_HTTP=1`) only when you must call a non-loopback `http://` control-plane endpoint.

### Handling governance verdicts

The two governance outcomes are thrown as typed errors. A denial must **not** be
blindly retried; an approval gate must **pause** for a human:

```ts
try {
  await rw.shell(sbx.id, ["rm", "-rf", "/"]);
} catch (err) {
  if (err instanceof RunewardDenied) {
    console.log("blocked by policy:", err.reason); // do NOT retry the same action
  }
}

try {
  await rw.writeFile(sbx.id, "/etc/hosts", "127.0.0.1 example");
} catch (err) {
  if (err instanceof RunewardApprovalRequired) {
    console.log("needs a human:", err.approvalId); // pause; approve/deny out-of-band
  }
}
```

## Client method surface

| Method | REST endpoint |
| --- | --- |
| `healthz()` | `GET /healthz` |
| `listProfiles()` | `GET /v1/profiles` |
| `createSandbox(profile)` | `POST /v1/sandboxes` |
| `listSandboxes()` / `getSandbox(id)` / `killSandbox(id)` | `GET`/`GET`/`DELETE /v1/sandboxes[/{id}]` |
| `shell(sandbox, command, workdir?)` | `POST .../shell/exec` |
| `python(sandbox, code)` / `node(sandbox, code)` | `POST .../code/{python,node}` |
| `readFile` / `writeFile` / `listFiles` / `searchFiles` | `POST .../file/{read,write,list,search}` |
| `audit(sandbox)` / `verifyAudit()` | `GET .../audit`, `GET /v1/audit/verify` |
| `listApprovals()` / `approve(id)` / `deny(id)` | `GET /v1/approvals`, `POST /v1/approvals/{id}/{approve,deny}` |

## Vercel AI SDK tools

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/ai-tools";

const tools = await makeRunewardTools(new RunewardClient());

const { text } = await generateText({
  model: openai("gpt-4o"),
  tools,
  maxSteps: 8,
  prompt: "Create a dev sandbox, run `node --version` in it, then tear it down.",
});
```

Tool names match the runeward MCP tools (`runeward_create_sandbox`,
`runeward_shell`, …). Governance verdicts are returned to the model as
descriptive strings so it can react to a denial or an approval gate instead of
crashing the run.

## LangChain.js tools

```ts
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/langchain-tools";

const tools = await makeRunewardTools(new RunewardClient());
const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o" }), tools });

const res = await agent.invoke({
  messages: [{ role: "user", content: "Create a dev sandbox, run `node --version`, then tear it down." }],
});
```

Returns `DynamicStructuredTool` instances (from `@langchain/core/tools`) with the
same runeward tool names and the same string-based verdict handling as above.

## Strands Agents SDK

```ts
import { Agent } from "@strands-agents/sdk";
import { RunewardClient } from "@runeward/sdk";
import { makeRunewardTools } from "@runeward/sdk/strands-tools";

const tools = await makeRunewardTools(new RunewardClient());
const agent = new Agent({ tools });

const res = await agent.invoke("Create a dev sandbox, run `node --version`, then tear it down.");
```

Returns Strands tools built with `tool({ name, description, inputSchema, callback })`
(Zod schemas), with the same runeward tool names and string-based verdict handling.

## Notes

- **`deny` is a policy decision, not a transient error.** Don't retry the same
  action; pick a different, allowed approach.
- **`require-approval` is a hard pause.** Surface the `approvalId` to a human and
  wait for the outcome.
- Prefer the tightest profile that lets the task succeed.
