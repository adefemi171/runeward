/**
 * Strands Agents SDK tool wrappers around {@link RunewardClient}.
 *
 * `@strands-agents/sdk` and `zod` are **optional peer dependencies** — this
 * module imports them at call time inside {@link makeRunewardTools} so the core
 * client stays dependency-free. Install them where you use the tools:
 *
 * ```bash
 * npm install @strands-agents/sdk zod
 * ```
 *
 * The optional peers are imported through a `string`-typed specifier so this
 * package type-checks and builds without them installed (and stays immune to
 * Strands type churn across major versions); the tool input shapes are typed
 * explicitly from the client instead of inferred from the framework.
 *
 * Each tool converts governance verdicts into a short, model-readable string
 * (rather than throwing) so the model can reason about a denial or an approval
 * gate: a `deny` must not be retried blindly, and a `require-approval` is a hard
 * pause for a human.
 */

import { RunewardApprovalRequired, RunewardClient, RunewardDenied } from "./client.js";

/** Turn a governance error into a model-friendly instruction; rethrow otherwise. */
function describeGovernance(err: unknown): string {
  if (err instanceof RunewardDenied) {
    return (
      `DENIED by policy: ${err.reason}. Do not retry this action; choose a ` +
      `different, allowed approach or tell the human it was blocked.`
    );
  }
  if (err instanceof RunewardApprovalRequired) {
    return (
      `APPROVAL REQUIRED (approval_id=${err.approvalId}): ` +
      `${err.reason || "a human must sign off before this runs"}. ` +
      `Pause the task and ask the human to approve or deny.`
    );
  }
  throw err;
}

/** Run `fn`, converting governance verdicts to strings for the model. */
async function guarded<T>(fn: () => Promise<T>): Promise<string> {
  try {
    const result = await fn();
    return typeof result === "string" ? result : JSON.stringify(result);
  } catch (err) {
    return describeGovernance(err);
  }
}

/**
 * Build an array of Strands Agents SDK tools bound to `client`, named to match
 * the runeward MCP tools. Pass them to `new Agent({ tools })`.
 *
 * @example
 * ```ts
 * import { Agent } from "@strands-agents/sdk";
 * import { RunewardClient } from "@runeward/sdk";
 * import { makeRunewardTools } from "@runeward/sdk/strands-tools";
 *
 * const tools = await makeRunewardTools(new RunewardClient());
 * const agent = new Agent({ tools });
 * await agent.invoke("Create a dev sandbox, run `node --version`, then tear it down.");
 * ```
 */
export async function makeRunewardTools(client: RunewardClient) {
  // Dynamic imports keep `@strands-agents/sdk` and `zod` as optional peers. The
  // `as string` specifier makes these fully dynamic so tsc does not require the
  // packages to be installed to build this file.
  const { tool } = await import("@strands-agents/sdk" as string);
  const { z } = await import("zod" as string);

  return [
    tool({
      name: "runeward_create_sandbox",
      description:
        "Provision a governed sandbox from a runeward profile (e.g. 'dev'). Returns sandbox metadata including its id.",
      inputSchema: z.object({
        profile: z.string().describe("Profile name, e.g. 'dev' or 'governed'."),
      }),
      callback: (input: { profile: string }) =>
        guarded(() => client.createSandbox(input.profile)),
    }),

    tool({
      name: "runeward_shell",
      description:
        "Run a shell command (as an argv array, e.g. ['ls','-la']) in a sandbox. Returns verdict, exit_code, stdout, stderr.",
      inputSchema: z.object({
        sandbox: z.string().describe("Sandbox id from create_sandbox."),
        command: z.array(z.string()).describe("argv array, e.g. ['ls','-la']."),
        workdir: z.string().optional().describe("Optional working directory."),
      }),
      callback: (input: { sandbox: string; command: string[]; workdir?: string }) =>
        guarded(() => client.shell(input.sandbox, input.command, input.workdir ?? "")),
    }),

    tool({
      name: "runeward_python",
      description: "Run a Python code snippet inside the sandbox.",
      inputSchema: z.object({
        sandbox: z.string(),
        code: z.string().describe("Python source to execute."),
      }),
      callback: (input: { sandbox: string; code: string }) =>
        guarded(() => client.python(input.sandbox, input.code)),
    }),

    tool({
      name: "runeward_node",
      description: "Run a Node.js code snippet inside the sandbox.",
      inputSchema: z.object({
        sandbox: z.string(),
        code: z.string().describe("JavaScript source to execute."),
      }),
      callback: (input: { sandbox: string; code: string }) =>
        guarded(() => client.node(input.sandbox, input.code)),
    }),

    tool({
      name: "runeward_read_file",
      description: "Read a file's contents from the sandbox.",
      inputSchema: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to read."),
      }),
      callback: (input: { sandbox: string; path: string }) =>
        guarded(() => client.readFile(input.sandbox, input.path)),
    }),

    tool({
      name: "runeward_write_file",
      description: "Write content to a file in the sandbox.",
      inputSchema: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to write."),
        content: z.string().describe("Content to write."),
      }),
      callback: (input: { sandbox: string; path: string; content: string }) =>
        guarded(async () => `wrote ${await client.writeFile(input.sandbox, input.path, input.content)} bytes to ${input.path}`),
    }),

    tool({
      name: "runeward_list_files",
      description: "List a directory in the sandbox.",
      inputSchema: z.object({
        sandbox: z.string(),
        path: z.string().describe("Directory path to list."),
      }),
      callback: (input: { sandbox: string; path: string }) =>
        guarded(() => client.listFiles(input.sandbox, input.path)),
    }),

    tool({
      name: "runeward_search_files",
      description: "Search for a query string under a path in the sandbox.",
      inputSchema: z.object({
        sandbox: z.string(),
        query: z.string().describe("Search query."),
        path: z.string().describe("Path to search under."),
      }),
      callback: (input: { sandbox: string; query: string; path: string }) =>
        guarded(() => client.searchFiles(input.sandbox, input.query, input.path)),
    }),

    tool({
      name: "runeward_list_approvals",
      description: "List pending human-in-the-loop approval requests.",
      inputSchema: z.object({}),
      callback: () => guarded(() => client.listApprovals()),
    }),

    tool({
      name: "runeward_kill_sandbox",
      description: "Tear down a sandbox when the task is finished.",
      inputSchema: z.object({
        sandbox: z.string(),
      }),
      callback: (input: { sandbox: string }) =>
        guarded(async () => {
          await client.killSandbox(input.sandbox);
          return `sandbox ${input.sandbox} terminated`;
        }),
    }),
  ];
}
