/**
 * LangChain.js tool wrappers around {@link RunewardClient}.
 *
 * `@langchain/core` and `zod` are **optional peer dependencies** — this module
 * imports them at call time inside {@link makeRunewardTools} so the core client
 * stays dependency-free. Install them where you use the tools:
 *
 * ```bash
 * npm install @langchain/core zod
 * ```
 *
 * The optional peers are imported through a `string`-typed specifier so this
 * package type-checks and builds without them installed (and stays immune to
 * LangChain type churn across major versions); the tool argument shapes are
 * typed explicitly from the client instead of inferred from the framework.
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
 * Build an array of LangChain.js `DynamicStructuredTool`s bound to `client`,
 * named to match the runeward MCP tools. Pass them to an agent (e.g.
 * `createReactAgent({ llm, tools })`) or bind them to a chat model with
 * `model.bindTools(tools)`.
 *
 * @example
 * ```ts
 * import { ChatOpenAI } from "@langchain/openai";
 * import { createReactAgent } from "@langchain/langgraph/prebuilt";
 * import { RunewardClient } from "@runeward/sdk";
 * import { makeRunewardTools } from "@runeward/sdk/langchain-tools";
 *
 * const tools = await makeRunewardTools(new RunewardClient());
 * const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o" }), tools });
 * ```
 */
export async function makeRunewardTools(client: RunewardClient) {
  // Dynamic imports keep `@langchain/core` and `zod` as optional peers. The
  // `as string` specifier makes these fully dynamic so tsc does not require the
  // packages to be installed to build this file.
  const { DynamicStructuredTool } = await import("@langchain/core/tools" as string);
  const { z } = await import("zod" as string);

  return [
    new DynamicStructuredTool({
      name: "runeward_create_sandbox",
      description:
        "Provision a governed sandbox from a runeward profile (e.g. 'dev'). Returns sandbox metadata including its id.",
      schema: z.object({
        profile: z.string().describe("Profile name, e.g. 'dev' or 'governed'."),
      }),
      func: async ({ profile }: { profile: string }) =>
        guarded(() => client.createSandbox(profile)),
    }),

    new DynamicStructuredTool({
      name: "runeward_shell",
      description:
        "Run a shell command (as an argv array, e.g. ['ls','-la']) in a sandbox. Returns verdict, exit_code, stdout, stderr.",
      schema: z.object({
        sandbox: z.string().describe("Sandbox id from create_sandbox."),
        command: z.array(z.string()).describe("argv array, e.g. ['ls','-la']."),
        workdir: z.string().optional().describe("Optional working directory."),
      }),
      func: async ({ sandbox, command, workdir }: { sandbox: string; command: string[]; workdir?: string }) =>
        guarded(() => client.shell(sandbox, command, workdir ?? "")),
    }),

    new DynamicStructuredTool({
      name: "runeward_python",
      description: "Run a Python code snippet inside the sandbox.",
      schema: z.object({
        sandbox: z.string(),
        code: z.string().describe("Python source to execute."),
      }),
      func: async ({ sandbox, code }: { sandbox: string; code: string }) =>
        guarded(() => client.python(sandbox, code)),
    }),

    new DynamicStructuredTool({
      name: "runeward_node",
      description: "Run a Node.js code snippet inside the sandbox.",
      schema: z.object({
        sandbox: z.string(),
        code: z.string().describe("JavaScript source to execute."),
      }),
      func: async ({ sandbox, code }: { sandbox: string; code: string }) =>
        guarded(() => client.node(sandbox, code)),
    }),

    new DynamicStructuredTool({
      name: "runeward_read_file",
      description: "Read a file's contents from the sandbox.",
      schema: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to read."),
      }),
      func: async ({ sandbox, path }: { sandbox: string; path: string }) =>
        guarded(() => client.readFile(sandbox, path)),
    }),

    new DynamicStructuredTool({
      name: "runeward_write_file",
      description: "Write content to a file in the sandbox.",
      schema: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to write."),
        content: z.string().describe("Content to write."),
      }),
      func: async ({ sandbox, path, content }: { sandbox: string; path: string; content: string }) =>
        guarded(async () => `wrote ${await client.writeFile(sandbox, path, content)} bytes to ${path}`),
    }),

    new DynamicStructuredTool({
      name: "runeward_list_files",
      description: "List a directory in the sandbox.",
      schema: z.object({
        sandbox: z.string(),
        path: z.string().describe("Directory path to list."),
      }),
      func: async ({ sandbox, path }: { sandbox: string; path: string }) =>
        guarded(() => client.listFiles(sandbox, path)),
    }),

    new DynamicStructuredTool({
      name: "runeward_search_files",
      description: "Search for a query string under a path in the sandbox.",
      schema: z.object({
        sandbox: z.string(),
        query: z.string().describe("Search query."),
        path: z.string().describe("Path to search under."),
      }),
      func: async ({ sandbox, query, path }: { sandbox: string; query: string; path: string }) =>
        guarded(() => client.searchFiles(sandbox, query, path)),
    }),

    new DynamicStructuredTool({
      name: "runeward_list_approvals",
      description: "List pending human-in-the-loop approval requests.",
      schema: z.object({}),
      func: async () => guarded(() => client.listApprovals()),
    }),

    new DynamicStructuredTool({
      name: "runeward_kill_sandbox",
      description: "Tear down a sandbox when the task is finished.",
      schema: z.object({
        sandbox: z.string(),
      }),
      func: async ({ sandbox }: { sandbox: string }) =>
        guarded(async () => {
          await client.killSandbox(sandbox);
          return `sandbox ${sandbox} terminated`;
        }),
    }),
  ];
}
