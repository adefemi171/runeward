// Package mcp exposes runeward's governed tools over the Model Context
// Protocol, going through the same policy/guardrails/audit path as the REST
// API. A policy deny surfaces as a tool error; require-approval returns
// guidance telling the agent to pause for a human rather than retry.
package mcp

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Runewardd/runeward/internal/authz"
	"github.com/Runewardd/runeward/internal/browser"
	"github.com/Runewardd/runeward/internal/controlplane"
	"github.com/Runewardd/runeward/internal/profile"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version is the reported MCP server implementation version.
const Version = "0.1.0"

const (
	// EnvMCPDefaultPrincipal names the stdio principal to use when no HTTP
	// request context exists.
	EnvMCPDefaultPrincipal = "RUNEWARD_MCP_DEFAULT_PRINCIPAL"
	// EnvMCPDefaultToken maps stdio sessions to an authz principal when
	// RUNEWARD_AUTHZ_FILE is configured.
	EnvMCPDefaultToken = "RUNEWARD_MCP_DEFAULT_TOKEN"
)

type principalIdentity struct {
	Owner     string
	Principal *authz.Principal
}

func (p principalIdentity) canLaunch(profileName string) bool {
	if p.Principal == nil {
		return true
	}
	return p.Principal.CanLaunch(profileName)
}

type principalResolver struct {
	store          *authz.Store
	stdioOwner     string
	stdioPrincipal *authz.Principal
}

func newPrincipalResolver() (*principalResolver, error) {
	store, err := authz.FromEnv()
	if err != nil {
		return nil, err
	}
	r := &principalResolver{
		store:      store,
		stdioOwner: strings.TrimSpace(os.Getenv(EnvMCPDefaultPrincipal)),
	}
	if r.stdioOwner == "" {
		r.stdioOwner = "mcp-stdio"
	}
	if store == nil {
		return r, nil
	}
	tok := strings.TrimSpace(os.Getenv(EnvMCPDefaultToken))
	if tok == "" {
		return nil, fmt.Errorf("%s is required when %s is configured", EnvMCPDefaultToken, authz.EnvFile)
	}
	p, ok := store.Identify(tok)
	if !ok {
		return nil, fmt.Errorf("%s does not match any principal in %s", EnvMCPDefaultToken, authz.EnvFile)
	}
	r.stdioOwner = p.Name
	r.stdioPrincipal = p
	return r, nil
}

func (r *principalResolver) resolve(req *sdk.CallToolRequest) (principalIdentity, error) {
	if req == nil || req.GetExtra() == nil {
		return principalIdentity{Owner: r.stdioOwner, Principal: r.stdioPrincipal}, nil
	}
	authHeader := ""
	if h := req.GetExtra().Header; h != nil {
		authHeader = h.Get("Authorization")
	}
	tok, ok := parseBearerToken(authHeader)
	if !ok {
		return principalIdentity{}, fmt.Errorf("missing bearer token")
	}
	if r.store == nil {
		return principalIdentity{}, fmt.Errorf("RBAC is not configured (%s unset)", authz.EnvFile)
	}
	p, ok := r.store.Identify(tok)
	if !ok {
		return principalIdentity{}, fmt.Errorf("unknown bearer token")
	}
	return principalIdentity{Owner: p.Name, Principal: p}, nil
}

func parseBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", false
	}
	if parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// NewServer builds an MCP server with runeward's governed tools registered
// against mgr.
func NewServer(mgr *controlplane.Manager) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "runeward", Version: Version}, nil)
	resolver, resolverErr := newPrincipalResolver()

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_create_sandbox",
		Description: "Provision a governed, isolated sandbox from a named runeward profile and return its id. Use this before running any other tool.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in struct {
		Profile  string `json:"profile" jsonschema:"the runeward profile to provision (e.g. dev)"`
		CopyFrom string `json:"copy_from,omitempty" jsonschema:"optional local directory whose contents are copied into the fresh workspace at creation (overrides the profile's host.copy_from)"`
	}) (*sdk.CallToolResult, any, error) {
		if resolverErr != nil {
			return errText(resolverErr), nil, nil
		}
		principal, err := resolver.resolve(req)
		if err != nil {
			return errText(err), nil, nil
		}
		if !principal.canLaunch(in.Profile) {
			return errText(fmt.Errorf("principal %q is not allowed to launch profile %q", principal.Owner, in.Profile)), nil, nil
		}
		sb, err := mgr.CreateSandbox(ctx, in.Profile, controlplane.CreateOptions{CopyFrom: in.CopyFrom, Owner: principal.Owner})
		if err != nil {
			return errText(err), nil, nil
		}
		return text(fmt.Sprintf("sandbox %s created (profile=%s backend=%s image=%s)", sb.ID, sb.Profile, sb.Backend, sb.Image)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_shell",
		Description: "Run a shell command (argv form) in a sandbox. Subject to policy: may be denied or require human approval.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string   `json:"sandbox" jsonschema:"the sandbox id"`
		Command []string `json:"command" jsonschema:"the command as an argv array, e.g. [\"ls\",\"-la\"]"`
		Workdir string   `json:"workdir,omitempty" jsonschema:"optional working directory"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.Shell(ctx, in.Sandbox, in.Command, in.Workdir)
		return execResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_browser",
		Description: "Fetch a URL with a headless browser inside the sandbox and return the rendered page. mode 'text' returns the rendered DOM HTML; 'screenshot' returns a base64 PNG. Subject to policy (tool 'browser', arg = url) and the profile's egress allowlist.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		URL     string `json:"url" jsonschema:"the URL to load"`
		Mode    string `json:"mode,omitempty" jsonschema:"'text' (default) or 'screenshot'"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.Browser(ctx, in.Sandbox, in.URL, in.Mode)
		return execResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_browser_open",
		Description: "Open a STATEFUL, CDP-driven browser session inside the sandbox and return its session id. The page (cookies, DOM, storage) persists across runeward_browser_act calls until runeward_browser_close. Subject to policy (tool 'browser') and the profile's egress allowlist.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
	}) (*sdk.CallToolResult, any, error) {
		sid, res, err := mgr.BrowserOpen(ctx, in.Sandbox)
		if err != nil {
			return errText(err), nil, nil
		}
		if res != nil && res.Verdict != profile.VerdictAllow {
			return execResult(res, nil), nil, nil
		}
		return text(fmt.Sprintf("browser session %s opened", sid)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_browser_act",
		Description: "Run one action against an open browser session. action is one of navigate|eval|text|html|screenshot|click|type|wait|title|url. Provide url (navigate), selector (click/type/wait), expr (eval JS), or text (type). Returns the textual value, or a base64 PNG for screenshot. Governed per action.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox   string `json:"sandbox" jsonschema:"the sandbox id"`
		Session   string `json:"session" jsonschema:"the browser session id from runeward_browser_open"`
		Action    string `json:"action" jsonschema:"navigate|eval|text|html|screenshot|click|type|wait|title|url"`
		URL       string `json:"url,omitempty" jsonschema:"URL for action=navigate"`
		Selector  string `json:"selector,omitempty" jsonschema:"CSS selector for click/type/wait"`
		Expr      string `json:"expr,omitempty" jsonschema:"JavaScript source for action=eval"`
		Text      string `json:"text,omitempty" jsonschema:"text to type for action=type"`
		TimeoutMS int    `json:"timeout_ms,omitempty" jsonschema:"optional per-action timeout in ms"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.BrowserAct(ctx, in.Sandbox, in.Session, browser.Command{
			Action: in.Action, URL: in.URL, Selector: in.Selector,
			Expr: in.Expr, Text: in.Text, TimeoutMS: in.TimeoutMS,
		})
		return execResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_browser_close",
		Description: "Close an open browser session (shuts down the in-sandbox Chromium and frees its resources).",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Session string `json:"session" jsonschema:"the browser session id"`
	}) (*sdk.CallToolResult, any, error) {
		if err := mgr.BrowserClose(ctx, in.Sandbox, in.Session); err != nil {
			return errText(err), nil, nil
		}
		return text(fmt.Sprintf("browser session %s closed", in.Session)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_python",
		Description: "Run a Python 3 snippet in a sandbox via python3 -c.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Code    string `json:"code" jsonschema:"Python source to execute"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.Python(ctx, in.Sandbox, in.Code)
		return execResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_node",
		Description: "Run a JavaScript snippet in a sandbox via node -e.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Code    string `json:"code" jsonschema:"JavaScript source to execute"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.Node(ctx, in.Sandbox, in.Code)
		return execResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_read_file",
		Description: "Read a file from a sandbox and return its contents.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Path    string `json:"path" jsonschema:"the file path to read"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.FileRead(ctx, in.Sandbox, in.Path)
		return rawResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_write_file",
		Description: "Write content to a file in a sandbox (creating parent directories). May require approval.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Path    string `json:"path" jsonschema:"the file path to write"`
		Content string `json:"content" jsonschema:"the file content"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.FileWrite(ctx, in.Sandbox, in.Path, in.Content)
		if blocked := blockedResult(res, err); blocked != nil {
			return blocked, nil, nil
		}
		return text(fmt.Sprintf("wrote %d bytes to %s", len(in.Content), in.Path)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_list_files",
		Description: "List a directory in a sandbox (ls -la).",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Path    string `json:"path,omitempty" jsonschema:"the directory to list (default .)"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.FileList(ctx, in.Sandbox, in.Path)
		return rawResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_search_files",
		Description: "Recursively search for text in a sandbox (grep -rn).",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
		Query   string `json:"query" jsonschema:"the text to search for"`
		Path    string `json:"path,omitempty" jsonschema:"the root to search under (default .)"`
	}) (*sdk.CallToolResult, any, error) {
		res, err := mgr.FileSearch(ctx, in.Sandbox, in.Query, in.Path)
		return rawResult(res, err), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_list_approvals",
		Description: "List pending human-in-the-loop approval requests across all sandboxes.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, any, error) {
		list := mgr.Approvals().List()
		if len(list) == 0 {
			return text("no pending approvals"), nil, nil
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
		var b strings.Builder
		for _, a := range list {
			fmt.Fprintf(&b, "%s  sandbox=%s  %s %q  reason=%s\n", a.ID, a.Sandbox, a.Tool, a.Action, a.Reason)
		}
		return text(b.String()), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_kill_sandbox",
		Description: "Tear down a sandbox and free its resources.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Sandbox string `json:"sandbox" jsonschema:"the sandbox id"`
	}) (*sdk.CallToolResult, any, error) {
		if err := mgr.KillSandbox(ctx, in.Sandbox); err != nil {
			return errText(err), nil, nil
		}
		return text("sandbox " + in.Sandbox + " terminated"), nil, nil
	})

	registerFleetTools(s, mgr, resolver, resolverErr)
	return s
}

// registerFleetTools adds the fleet orchestration tools (a fleet is N sandboxes
// sharing a task board).
func registerFleetTools(s *sdk.Server, mgr *controlplane.Manager, resolver *principalResolver, resolverErr error) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_create_fleet",
		Description: "Provision a fleet: N governed sandboxes (from the profile's [fleet].replicas) sharing an atomic task board seeded from the profile's task_board. Returns the fleet id and member sandbox ids.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in struct {
		Profile string `json:"profile" jsonschema:"the runeward profile to provision the fleet from"`
	}) (*sdk.CallToolResult, any, error) {
		if resolverErr != nil {
			return errText(resolverErr), nil, nil
		}
		principal, err := resolver.resolve(req)
		if err != nil {
			return errText(err), nil, nil
		}
		if !principal.canLaunch(in.Profile) {
			return errText(fmt.Errorf("principal %q is not allowed to launch profile %q", principal.Owner, in.Profile)), nil, nil
		}
		v, err := mgr.CreateFleet(ctx, in.Profile)
		if err != nil {
			return errText(err), nil, nil
		}
		return text(fmt.Sprintf("fleet %s created (profile=%s, %d sandboxes: %s; tasks total=%d pending=%d)",
			v.ID, v.Profile, len(v.Sandboxes), strings.Join(v.Sandboxes, ", "), v.Stats.Total, v.Stats.Pending)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_list_fleets",
		Description: "List all fleets with their sandbox members and task-board stats.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, any, error) {
		fleets := mgr.ListFleets()
		if len(fleets) == 0 {
			return text("no fleets"), nil, nil
		}
		var b strings.Builder
		for _, v := range fleets {
			fmt.Fprintf(&b, "%s  profile=%s  sandboxes=%d  tasks[total=%d pending=%d claimed=%d done=%d failed=%d]\n",
				v.ID, v.Profile, len(v.Sandboxes), v.Stats.Total, v.Stats.Pending, v.Stats.Claimed, v.Stats.Done, v.Stats.Failed)
		}
		return text(b.String()), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_list_tasks",
		Description: "List the tasks on a fleet's board with their state, owner, and results.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Fleet string `json:"fleet" jsonschema:"the fleet id"`
	}) (*sdk.CallToolResult, any, error) {
		tasks, err := mgr.ListTasks(in.Fleet)
		if err != nil {
			return errText(err), nil, nil
		}
		if len(tasks) == 0 {
			return text("no tasks"), nil, nil
		}
		var b strings.Builder
		for _, t := range tasks {
			fmt.Fprintf(&b, "%s  [%s]  owner=%s attempts=%d  %q", t.ID, t.State, t.Owner, t.Attempts, t.Payload)
			if t.Result != "" {
				fmt.Fprintf(&b, "  result=%q", t.Result)
			}
			if t.Error != "" {
				fmt.Fprintf(&b, "  error=%q", t.Error)
			}
			b.WriteByte('\n')
		}
		return text(b.String()), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_add_task",
		Description: "Add a task to a fleet's board.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Fleet   string `json:"fleet" jsonschema:"the fleet id"`
		Payload string `json:"payload" jsonschema:"the task description/payload"`
	}) (*sdk.CallToolResult, any, error) {
		t, err := mgr.AddTask(in.Fleet, in.Payload)
		if err != nil {
			return errText(err), nil, nil
		}
		return text(fmt.Sprintf("added task %s: %q", t.ID, t.Payload)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_claim_task",
		Description: "Atomically claim the next pending task from a fleet's board for a worker. Returns the task, or reports the board is empty.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in struct {
		Fleet string `json:"fleet" jsonschema:"the fleet id"`
		Owner string `json:"owner" jsonschema:"an identifier for the claiming worker"`
	}) (*sdk.CallToolResult, any, error) {
		if resolverErr != nil {
			return errText(resolverErr), nil, nil
		}
		principal, err := resolver.resolve(req)
		if err != nil {
			return errText(err), nil, nil
		}
		if in.Owner != "" && in.Owner != principal.Owner {
			return errText(fmt.Errorf("owner must match authenticated principal %q", principal.Owner)), nil, nil
		}
		t, ok, err := mgr.ClaimTask(in.Fleet, principal.Owner)
		if err != nil {
			return errText(err), nil, nil
		}
		if !ok {
			return text("no pending tasks to claim"), nil, nil
		}
		return text(fmt.Sprintf("claimed task %s (attempt %d): %q", t.ID, t.Attempts, t.Payload)), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_heartbeat_task",
		Description: "Extend the lease on a task a worker still holds so the fleet sweeper does not requeue it as a dead worker.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in struct {
		Fleet string `json:"fleet" jsonschema:"the fleet id"`
		Task  string `json:"task" jsonschema:"the task id"`
		Owner string `json:"owner" jsonschema:"the worker that holds the claim"`
	}) (*sdk.CallToolResult, any, error) {
		if resolverErr != nil {
			return errText(resolverErr), nil, nil
		}
		principal, err := resolver.resolve(req)
		if err != nil {
			return errText(err), nil, nil
		}
		if in.Owner != "" && in.Owner != principal.Owner {
			return errText(fmt.Errorf("owner must match authenticated principal %q", principal.Owner)), nil, nil
		}
		t, err := mgr.HeartbeatTask(in.Fleet, in.Task, principal.Owner)
		if err != nil {
			return errText(err), nil, nil
		}
		return text(fmt.Sprintf("task %s lease extended (expires %s)", t.ID, t.LeaseExpiry.Format("15:04:05"))), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_complete_task",
		Description: "Mark a claimed task as done with its result.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in struct {
		Fleet  string `json:"fleet" jsonschema:"the fleet id"`
		Task   string `json:"task" jsonschema:"the task id"`
		Owner  string `json:"owner,omitempty" jsonschema:"the worker that holds the claim"`
		Result string `json:"result,omitempty" jsonschema:"the successful result output"`
	}) (*sdk.CallToolResult, any, error) {
		if resolverErr != nil {
			return errText(resolverErr), nil, nil
		}
		principal, err := resolver.resolve(req)
		if err != nil {
			return errText(err), nil, nil
		}
		if in.Owner != "" && in.Owner != principal.Owner {
			return errText(fmt.Errorf("owner must match authenticated principal %q", principal.Owner)), nil, nil
		}
		if err := mgr.CompleteTask(in.Fleet, in.Task, principal.Owner, in.Result); err != nil {
			return errText(err), nil, nil
		}
		return text("task " + in.Task + " completed"), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_fail_task",
		Description: "Mark a claimed task as failed. Set requeue=true to return it to the pending pool for retry.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in struct {
		Fleet   string `json:"fleet" jsonschema:"the fleet id"`
		Task    string `json:"task" jsonschema:"the task id"`
		Owner   string `json:"owner,omitempty" jsonschema:"the worker that holds the claim"`
		Error   string `json:"error,omitempty" jsonschema:"the failure message"`
		Requeue bool   `json:"requeue,omitempty" jsonschema:"whether to requeue the task for retry"`
	}) (*sdk.CallToolResult, any, error) {
		if resolverErr != nil {
			return errText(resolverErr), nil, nil
		}
		principal, err := resolver.resolve(req)
		if err != nil {
			return errText(err), nil, nil
		}
		if in.Owner != "" && in.Owner != principal.Owner {
			return errText(fmt.Errorf("owner must match authenticated principal %q", principal.Owner)), nil, nil
		}
		if err := mgr.FailTask(in.Fleet, in.Task, principal.Owner, in.Error, in.Requeue); err != nil {
			return errText(err), nil, nil
		}
		verb := "failed"
		if in.Requeue {
			verb = "failed and requeued"
		}
		return text("task " + in.Task + " " + verb), nil, nil
	})

	sdk.AddTool(s, &sdk.Tool{
		Name:        "runeward_kill_fleet",
		Description: "Tear down a fleet and all its sandboxes.",
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in struct {
		Fleet string `json:"fleet" jsonschema:"the fleet id"`
	}) (*sdk.CallToolResult, any, error) {
		if err := mgr.KillFleet(ctx, in.Fleet); err != nil {
			return errText(err), nil, nil
		}
		return text("fleet " + in.Fleet + " terminated"), nil, nil
	})
}

func content(s string) []sdk.Content { return []sdk.Content{&sdk.TextContent{Text: s}} }

func text(s string) *sdk.CallToolResult { return &sdk.CallToolResult{Content: content(s)} }

func errText(err error) *sdk.CallToolResult {
	return &sdk.CallToolResult{IsError: true, Content: content("error: " + err.Error())}
}

// blockedResult is non-nil when the call errored, was denied, or is pending
// approval; nil means the caller formats success.
func blockedResult(res *controlplane.ToolResult, err error) *sdk.CallToolResult {
	if err != nil {
		return errText(err)
	}
	switch res.Verdict {
	case profile.VerdictDeny:
		return &sdk.CallToolResult{IsError: true, Content: content("DENIED by policy: " + res.Reason)}
	case profile.VerdictRequireApprove:
		return text(fmt.Sprintf("APPROVAL REQUIRED (approval id %s): %s. Pause and ask a human to approve this via the runeward approvals inbox before retrying; do not attempt to bypass it.", res.ApprovalID, res.Reason))
	}
	return nil
}

// execResult formats an exec-style result (exit code plus stdout/stderr).
func execResult(res *controlplane.ToolResult, err error) *sdk.CallToolResult {
	if blocked := blockedResult(res, err); blocked != nil {
		return blocked
	}
	var b strings.Builder
	fmt.Fprintf(&b, "exit=%d (%dms)\n", res.ExitCode, res.DurationMS)
	if res.Stdout != "" {
		b.WriteString("stdout:\n" + res.Stdout)
		if !strings.HasSuffix(res.Stdout, "\n") {
			b.WriteByte('\n')
		}
	}
	if res.Stderr != "" {
		b.WriteString("stderr:\n" + res.Stderr)
	}
	return text(strings.TrimRight(b.String(), "\n"))
}

// rawResult returns just the stdout on success (read/list/search).
func rawResult(res *controlplane.ToolResult, err error) *sdk.CallToolResult {
	if blocked := blockedResult(res, err); blocked != nil {
		return blocked
	}
	return text(res.Stdout)
}
