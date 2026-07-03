package profile

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// redacted is the placeholder shown in place of secret values.
const redacted = "«redacted»"

// Print renders a human-readable view of the resolved profile. Secret env
// values are never shown, only their source kind.
func Print(w io.Writer, p *Profile) {
	fmt.Fprintf(w, "profile: %s\n", p.Name)
	fmt.Fprintf(w, "source:  %s\n", p.Source)
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "host.type\t%s\n", p.Host.Type)
	if p.Host.Name != "" {
		fmt.Fprintf(tw, "host.name\t%s\n", p.Host.Name)
	}
	fmt.Fprintf(tw, "host.image\t%s\n", p.Host.Image)
	fmt.Fprintf(tw, "host.workdir\t%s\n", p.Host.Workdir)
	if p.Host.User != "" {
		fmt.Fprintf(tw, "host.user\t%s\n", p.Host.User)
	}
	if p.Host.CopyFrom != "" {
		fmt.Fprintf(tw, "host.copy_from\t%s (copied into workspace at create)\n", p.Host.CopyFrom)
	}
	if p.Host.RuntimeClass != "" {
		fmt.Fprintf(tw, "host.runtime_class\t%s\n", p.Host.RuntimeClass)
	}
	tw.Flush()

	if p.Prompt.Inline != "" || p.Prompt.File != "" {
		fmt.Fprintln(w, "\n[prompt]")
		if p.Prompt.File != "" {
			fmt.Fprintf(w, "  file: %s\n", p.Prompt.File)
		}
		if p.Prompt.Inline != "" {
			fmt.Fprintf(w, "  inline: %s\n", firstLine(p.Prompt.Inline))
		}
	}

	if len(p.Env) > 0 {
		fmt.Fprintln(w, "\n[env]")
		etw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, e := range p.Env {
			fmt.Fprintf(etw, "  %s\t= %s\t(%s)\n", e.Name, envDisplay(e), envSource(e))
		}
		etw.Flush()
	}

	if len(p.Files) > 0 {
		fmt.Fprintln(w, "\n[files]")
		for _, f := range p.Files {
			mode := f.Mode
			if mode == "" {
				mode = "0444"
			}
			fmt.Fprintf(w, "  %s (mode %s)\n", f.Path, mode)
		}
	}

	fmt.Fprintln(w, "\n[network]")
	if p.Network.DenyByDefault() {
		fmt.Fprintln(w, "  default: deny (allowlist below)")
	} else {
		fmt.Fprintln(w, "  default: allow (OPEN — no egress restriction)")
	}
	for _, r := range p.Network.Rules {
		target := r.Hostname
		if target == "" {
			target = r.CIDR
		}
		v := r.Verdict
		if v == "" {
			v = "allow"
		}
		fmt.Fprintf(w, "  %-5s %s\n", v, target)
	}

	if p.UsesCEL() {
		fmt.Fprintln(w, "\n[policy] engine: cel")
		ptw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, r := range p.CEL {
			v := r.Verdict
			if v == "" {
				v = VerdictAllow
			}
			fmt.Fprintf(ptw, "  %s\t-> %s\n", r.Expr, v)
		}
		ptw.Flush()
	} else if len(p.Policy) > 0 {
		fmt.Fprintln(w, "\n[policy] engine: builtin")
		ptw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, r := range p.Policy {
			match := r.Match
			if match == "" {
				match = "*"
			}
			fmt.Fprintf(ptw, "  %s\t%s\t-> %s\n", r.Tool, match, r.Verdict)
		}
		ptw.Flush()
	}

	if l := p.Limits; l != (Limits{}) {
		fmt.Fprintln(w, "\n[limits]")
		if l.WallClock != "" {
			fmt.Fprintf(w, "  wall_clock: %s\n", l.WallClock)
		}
		if l.MaxExecs > 0 {
			fmt.Fprintf(w, "  max_execs: %d\n", l.MaxExecs)
		}
		if l.EgressRequests > 0 {
			fmt.Fprintf(w, "  egress_requests: %d\n", l.EgressRequests)
		}
		if l.LoopThreshold > 0 {
			fmt.Fprintf(w, "  loop: %d within %s\n", l.LoopThreshold, orDefault(l.LoopWindow, "60s"))
		}
	}

	if p.Fleet != nil {
		fmt.Fprintln(w, "\n[fleet]")
		fmt.Fprintf(w, "  replicas: %d\n", p.Fleet.Replicas)
		if len(p.Fleet.TaskBoard) > 0 {
			fmt.Fprintf(w, "  tasks: %d seeded\n", len(p.Fleet.TaskBoard))
		}
	}

	fmt.Fprintln(w, "\n[audit]")
	fmt.Fprintf(w, "  redact: %t\n", p.Audit.RedactEnabled())
	if p.Audit.Sink != "" {
		fmt.Fprintf(w, "  sink: %s\n", p.Audit.Sink)
	}
}

func envDisplay(e EnvVar) string {
	if e.Secret() {
		return redacted
	}
	if e.Value != "" {
		return e.Value
	}
	return redacted
}

func envSource(e EnvVar) string {
	switch {
	case e.Op != "":
		return "1password"
	case e.File != "":
		return "file"
	case e.Value != "":
		return "literal"
	default:
		return "unset"
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
