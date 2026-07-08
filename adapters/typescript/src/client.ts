/**
 * A dependency-light TypeScript client for the runeward control plane.
 *
 * Uses the global `fetch` (Node 18+, Deno, Bun, browsers) so the core client
 * has **no runtime dependencies**. It mirrors the runeward REST contract 1:1 and
 * translates the two governance outcomes into typed errors:
 *
 * - HTTP `403` -> {@link RunewardDenied}
 * - HTTP `202` -> {@link RunewardApprovalRequired} (carries the `approvalId`)
 *
 * Any other non-2xx response becomes a {@link RunewardError}.
 */

/** Metadata returned when a sandbox is created or fetched. */
export interface Sandbox {
  id: string;
  profile: string;
  backend: string;
  image: string;
  status: string;
}

/** A profile advertised by the control plane. */
export interface Profile {
  name: string;
  host: string;
  egress: string;
}

/** The result of a governed execution (shell / python / node). */
export interface ExecResult {
  verdict: "allow" | "deny" | "require-approval";
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
}

/** A pending human-in-the-loop approval request. */
export interface Approval {
  id: string;
  sandbox: string;
  tool: string;
  action: string;
  reason: string;
  created: string;
}

/** Base error for any non-success response from the control plane. */
export class RunewardError extends Error {
  readonly status?: number;
  readonly payload: Record<string, unknown>;

  constructor(message: string, status?: number, payload: Record<string, unknown> = {}) {
    super(message);
    this.name = "RunewardError";
    this.status = status;
    this.payload = payload;
  }
}

/**
 * Thrown when policy denies an action (HTTP 403). A denial is a policy
 * decision, not a transient failure — do not retry the identical action.
 */
export class RunewardDenied extends RunewardError {
  readonly reason: string;

  constructor(reason: string, payload: Record<string, unknown> = {}) {
    super(`runeward denied action: ${reason}`, 403, payload);
    this.name = "RunewardDenied";
    this.reason = reason;
  }
}

/**
 * Thrown when an action needs human approval (HTTP 202). Pause and surface the
 * `approvalId` to a human rather than working around the gate.
 */
export class RunewardApprovalRequired extends RunewardError {
  readonly approvalId: string;
  readonly reason: string;

  constructor(approvalId: string, reason = "", payload: Record<string, unknown> = {}) {
    super(`runeward requires approval (id=${approvalId})${reason ? `: ${reason}` : ""}`, 202, payload);
    this.name = "RunewardApprovalRequired";
    this.approvalId = approvalId;
    this.reason = reason;
  }
}

/** Options for constructing a {@link RunewardClient}. */
export interface RunewardClientOptions {
  /** Control-plane base URL. Defaults to `http://localhost:8080`. */
  baseUrl?: string;
  /** Optional bearer token if the control plane requires auth. */
  token?: string;
  /** Per-request timeout in milliseconds. Defaults to 60_000. */
  timeoutMs?: number;
  /** Allow insecure `http://` to non-loopback hosts. */
  allowInsecure?: boolean;
}

/**
 * Thin, promise-based client over the runeward REST control plane.
 *
 * @example
 * ```ts
 * const rw = new RunewardClient({ baseUrl: "http://localhost:8080" });
 * const sbx = await rw.createSandbox("dev");
 * const out = await rw.shell(sbx.id, ["echo", "hello"]);
 * console.log(out.stdout); // "hello\n"
 * await rw.killSandbox(sbx.id);
 * ```
 */
export class RunewardClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;

  constructor(options: RunewardClientOptions = {}) {
    // Normalize so path joins never double up slashes.
    this.baseUrl = this.normalizeBaseUrl(options.baseUrl ?? "http://localhost:8080");
    this.validateTransport(this.baseUrl, options.allowInsecure ?? false);
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 60_000;
  }

  private normalizeBaseUrl(baseUrl: string): string {
    const trimmed = baseUrl.trim();
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    return withScheme.replace(/\/+$/, "");
  }

  private isLoopbackHost(hostname: string): boolean {
    const host = hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
  }

  private envAllowsInsecure(): boolean {
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
    const raw = env?.RUNEWARD_ALLOW_INSECURE_HTTP;
    if (!raw) return false;
    const value = raw.trim().toLowerCase();
    return value === "1" || value === "true" || value === "yes" || value === "on";
  }

  private validateTransport(baseUrl: string, allowInsecure: boolean): void {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "http:") return;
    if (this.isLoopbackHost(parsed.hostname)) return;
    if (allowInsecure || this.envAllowsInsecure()) {
      console.warn(`runeward client using insecure HTTP transport to non-loopback host: ${baseUrl}`);
      return;
    }
    throw new Error(
      "refusing insecure http:// base URL to non-loopback host; use https://, set allowInsecure: true, or set RUNEWARD_ALLOW_INSECURE_HTTP=1",
    );
  }

  private segment(value: string): string {
    return encodeURIComponent(value);
  }

  // -- low-level request plumbing --------------------------------------

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let resp: Response;
    try {
      resp = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      throw new RunewardError(`could not reach runeward at ${url}: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    const payload = await this.safeJson(resp);

    // 202 is a "successful" status to fetch but means an approval gate here.
    if (!resp.ok || resp.status === 202) {
      this.raiseForStatus(resp.status, payload);
    }
    return payload as T;
  }

  private async safeJson(resp: Response): Promise<Record<string, unknown>> {
    const text = await resp.text();
    if (!text) return {};
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return { raw: text };
    }
  }

  private raiseForStatus(status: number, payload: Record<string, unknown>): never {
    if (status === 403 || payload.verdict === "deny") {
      throw new RunewardDenied(String(payload.reason ?? "denied by policy"), payload);
    }
    if (status === 202 || payload.verdict === "require-approval") {
      throw new RunewardApprovalRequired(
        String(payload.approval_id ?? ""),
        String(payload.reason ?? ""),
        payload,
      );
    }
    throw new RunewardError(`runeward returned HTTP ${status}: ${JSON.stringify(payload)}`, status, payload);
  }

  // -- health & discovery ----------------------------------------------

  /** `GET /healthz` — liveness check. */
  healthz(): Promise<unknown> {
    return this.request("GET", "/healthz");
  }

  /** `GET /v1/profiles` — reachable profiles. */
  async listProfiles(): Promise<Profile[]> {
    const res = await this.request<{ profiles: Profile[] }>("GET", "/v1/profiles");
    return res.profiles ?? [];
  }

  // -- sandbox lifecycle -----------------------------------------------

  /** `POST /v1/sandboxes` — provision a sandbox from `profile`. */
  createSandbox(profile: string): Promise<Sandbox> {
    return this.request<Sandbox>("POST", "/v1/sandboxes", { profile });
  }

  /** `GET /v1/sandboxes`. */
  async listSandboxes(): Promise<Sandbox[]> {
    const res = await this.request<{ sandboxes: Sandbox[] }>("GET", "/v1/sandboxes");
    return res.sandboxes ?? [];
  }

  /** `GET /v1/sandboxes/{id}`. */
  getSandbox(sandbox: string): Promise<Sandbox> {
    return this.request<Sandbox>("GET", `/v1/sandboxes/${this.segment(sandbox)}`);
  }

  /** `DELETE /v1/sandboxes/{id}` — tear the sandbox down. */
  killSandbox(sandbox: string): Promise<unknown> {
    return this.request("DELETE", `/v1/sandboxes/${this.segment(sandbox)}`);
  }

  // -- execution -------------------------------------------------------

  /**
   * `POST .../shell/exec` — run `command` (an argv array) in the sandbox.
   * An `allow` verdict with a non-zero `exit_code` is a normal program error,
   * not a policy denial.
   */
  shell(sandbox: string, command: string[], workdir = ""): Promise<ExecResult> {
    return this.request<ExecResult>("POST", `/v1/sandboxes/${this.segment(sandbox)}/shell/exec`, { command, workdir });
  }

  /** `POST .../code/python` — run a Python snippet in the sandbox. */
  python(sandbox: string, code: string): Promise<ExecResult> {
    return this.request<ExecResult>("POST", `/v1/sandboxes/${this.segment(sandbox)}/code/python`, { code });
  }

  /** `POST .../code/node` — run a Node.js snippet in the sandbox. */
  node(sandbox: string, code: string): Promise<ExecResult> {
    return this.request<ExecResult>("POST", `/v1/sandboxes/${this.segment(sandbox)}/code/node`, { code });
  }

  // -- files -----------------------------------------------------------

  /** `POST .../file/read` — return the file's content. */
  async readFile(sandbox: string, path: string): Promise<string> {
    const res = await this.request<{ content: string }>("POST", `/v1/sandboxes/${this.segment(sandbox)}/file/read`, { path });
    return res.content ?? "";
  }

  /** `POST .../file/write` — write `content`; return the number of bytes written. */
  async writeFile(sandbox: string, path: string, content: string): Promise<number> {
    const res = await this.request<{ bytes: number }>("POST", `/v1/sandboxes/${this.segment(sandbox)}/file/write`, { path, content });
    return res.bytes ?? 0;
  }

  /** `POST .../file/list` — list a directory; return the raw output. */
  async listFiles(sandbox: string, path: string): Promise<string> {
    const res = await this.request<{ output: string }>("POST", `/v1/sandboxes/${this.segment(sandbox)}/file/list`, { path });
    return res.output ?? "";
  }

  /** `POST .../file/search` — search for `query` under `path`. */
  async searchFiles(sandbox: string, query: string, path: string): Promise<string> {
    const res = await this.request<{ output: string }>("POST", `/v1/sandboxes/${this.segment(sandbox)}/file/search`, { query, path });
    return res.output ?? "";
  }

  // -- audit -----------------------------------------------------------

  /** `GET .../audit` — this sandbox's ledger events. */
  async audit(sandbox: string): Promise<Array<Record<string, unknown>>> {
    const res = await this.request<{ events: Array<Record<string, unknown>> }>(
      "GET",
      `/v1/sandboxes/${this.segment(sandbox)}/audit`,
    );
    return res.events ?? [];
  }

  /** `GET /v1/audit/verify` — verify the ledger hash chain. */
  async verifyAudit(): Promise<boolean> {
    const res = await this.request<{ ok: boolean }>("GET", "/v1/audit/verify");
    return Boolean(res.ok);
  }

  // -- approvals -------------------------------------------------------

  /** `GET /v1/approvals` — pending human-in-the-loop requests. */
  async listApprovals(): Promise<Approval[]> {
    const res = await this.request<{ approvals: Approval[] }>("GET", "/v1/approvals");
    return res.approvals ?? [];
  }

  /** `POST /v1/approvals/{id}/approve`. */
  approve(approvalId: string): Promise<unknown> {
    return this.request("POST", `/v1/approvals/${this.segment(approvalId)}/approve`);
  }

  /** `POST /v1/approvals/{id}/deny`. */
  deny(approvalId: string): Promise<unknown> {
    return this.request("POST", `/v1/approvals/${this.segment(approvalId)}/deny`);
  }
}
