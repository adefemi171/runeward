/**
 * Vercel AI SDK tool wrappers around {@link RunewardClient}.
 *
 * `ai` and `zod` are **optional peer dependencies** — this module imports them
 * at call time inside {@link makeRunewardTools} so the core client stays
 * dependency-free. Install them where you use the tools:
 *
 * ```bash
 * npm install ai zod
 * ```
 *
 * The optional peers are imported through a `string`-typed specifier so this
 * package type-checks and builds without them installed (and stays immune to
 * AI-SDK type churn across major versions); the tool argument shapes are typed
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
 * Build a map of Vercel AI SDK tools bound to `client`, keyed by the runeward
 * MCP tool names. Spread the result into a `tools` object passed to
 * `generateText` / `streamText`.
 *
 * @example
 * ```ts
 * import { generateText } from "ai";
 * import { openai } from "@ai-sdk/openai";
 * import { RunewardClient } from "@runeward/sdk";
 * import { makeRunewardTools } from "@runeward/sdk/ai-tools";
 *
 * const tools = await makeRunewardTools(new RunewardClient());
 * await generateText({ model: openai("gpt-4o"), tools, prompt: "..." });
 * ```
 */
export async function makeRunewardTools(client: RunewardClient) {
  // Dynamic imports keep `ai` and `zod` as optional peers. The `as string`
  // specifier makes these fully dynamic so tsc does not require the packages
  // to be installed to build this file.
  const { tool } = await import("ai" as string);
  const { z } = await import("zod" as string);

  return {
    runeward_create_sandbox: tool({
      description:
        "Provision a governed sandbox from a runeward profile (e.g. 'dev'). Returns sandbox metadata including its id.",
      parameters: z.object({
        profile: z.string().describe("Profile name, e.g. 'dev' or 'governed'."),
      }),
      execute: ({ profile }: { profile: string }) =>
        guarded(() => client.createSandbox(profile)),
    }),

    runeward_shell: tool({
      description:
        "Run a shell command (as an argv array, e.g. ['ls','-la']) in a sandbox. Returns verdict, exit_code, stdout, stderr.",
      parameters: z.object({
        sandbox: z.string().describe("Sandbox id from create_sandbox."),
        command: z.array(z.string()).describe("argv array, e.g. ['ls','-la']."),
        workdir: z.string().optional().describe("Optional working directory."),
      }),
      execute: ({ sandbox, command, workdir }: { sandbox: string; command: string[]; workdir?: string }) =>
        guarded(() => client.shell(sandbox, command, workdir ?? "")),
    }),

    runeward_python: tool({
      description: "Run a Python code snippet inside the sandbox.",
      parameters: z.object({
        sandbox: z.string(),
        code: z.string().describe("Python source to execute."),
      }),
      execute: ({ sandbox, code }: { sandbox: string; code: string }) =>
        guarded(() => client.python(sandbox, code)),
    }),

    runeward_node: tool({
      description: "Run a Node.js code snippet inside the sandbox.",
      parameters: z.object({
        sandbox: z.string(),
        code: z.string().describe("JavaScript source to execute."),
      }),
      execute: ({ sandbox, code }: { sandbox: string; code: string }) =>
        guarded(() => client.node(sandbox, code)),
    }),

    runeward_read_file: tool({
      description: "Read a file's contents from the sandbox.",
      parameters: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to read."),
      }),
      execute: ({ sandbox, path }: { sandbox: string; path: string }) =>
        guarded(() => client.readFile(sandbox, path)),
    }),

    runeward_write_file: tool({
      description: "Write content to a file in the sandbox.",
      parameters: z.object({
        sandbox: z.string(),
        path: z.string().describe("File path to write."),
        content: z.string().describe("Content to write."),
      }),
      execute: ({ sandbox, path, content }: { sandbox: string; path: string; content: string }) =>
        guarded(async () => `wrote ${await client.writeFile(sandbox, path, content)} bytes to ${path}`),
    }),

    runeward_list_files: tool({
      description: "List a directory in the sandbox.",
      parameters: z.object({
        sandbox: z.string(),
        path: z.string().describe("Directory path to list."),
      }),
      execute: ({ sandbox, path }: { sandbox: string; path: string }) =>
        guarded(() => client.listFiles(sandbox, path)),
    }),

    runeward_search_files: tool({
      description: "Search for a query string under a path in the sandbox.",
      parameters: z.object({
        sandbox: z.string(),
        query: z.string().describe("Search query."),
        path: z.string().describe("Path to search under."),
      }),
      execute: ({ sandbox, query, path }: { sandbox: string; query: string; path: string }) =>
        guarded(() => client.searchFiles(sandbox, query, path)),
    }),

    runeward_list_approvals: tool({
      description: "List pending human-in-the-loop approval requests.",
      parameters: z.object({}),
      execute: () => guarded(() => client.listApprovals()),
    }),

    runeward_kill_sandbox: tool({
      description: "Tear down a sandbox when the task is finished.",
      parameters: z.object({
        sandbox: z.string(),
      }),
      execute: ({ sandbox }: { sandbox: string }) =>
        guarded(async () => {
          await client.killSandbox(sandbox);
          return `sandbox ${sandbox} terminated`;
        }),
    }),
  };
}
