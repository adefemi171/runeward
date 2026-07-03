package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/adefemi171/runeward/internal/backend"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newEnterCmd(configDir *string) *cobra.Command {
	var keep bool

	cmd := &cobra.Command{
		Use:   "enter <profile> [-- command...]",
		Short: "Provision a sandbox for a profile and step into it",
		Long: "Provision a sandbox for the named profile and attach an interactive\n" +
			"shell, or run an explicit command after `--`.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			inner := args[1:]

			p, err := loadProfile(name, *configDir)
			if err != nil {
				return err
			}
			env, warnings := resolveEnv(p)
			for _, w := range warnings {
				fmt.Fprintln(os.Stderr, "warning:", w)
			}

			be, err := backend.For(p)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			fmt.Fprintf(os.Stderr, "runeward: provisioning %q via %s backend...\n", name, be.Name())
			spec := backend.SpecFromProfile(p, env)
			sb, err := be.Create(ctx, spec)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "runeward: sandbox %s ready\n", sb.ID)

			if !keep {
				defer func() {
					fmt.Fprintf(os.Stderr, "\nruneward: tearing down sandbox %s\n", sb.ID)
					_ = be.Kill(context.Background(), sb.ID)
				}()
			} else {
				defer fmt.Fprintf(os.Stderr, "runeward: sandbox %s kept (id: %s)\n", sb.ID, sb.ID)
			}

			if len(inner) > 0 {
				return runInner(ctx, be, sb.ID, inner, p.Host.Workdir)
			}
			return attachShell(ctx, be, sb.ID)
		},
	}
	cmd.Flags().BoolVar(&keep, "keep", false, "do not tear down the sandbox on exit")
	return cmd
}

func runInner(ctx context.Context, be backend.Backend, id string, command []string, workdir string) error {
	res, err := be.Exec(ctx, id, backend.ExecRequest{Command: command, Workdir: workdir})
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, res.Stdout)
	fmt.Fprint(os.Stderr, res.Stderr)
	if res.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", res.ExitCode)
	}
	return nil
}

func attachShell(ctx context.Context, be backend.Backend, id string) error {
	stdinFd := int(os.Stdin.Fd())
	isTTY := term.IsTerminal(stdinFd)

	stream := backend.PTYStream{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		TTY:    isTTY,
	}

	if isTTY {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return fmt.Errorf("set raw terminal: %w", err)
		}
		defer term.Restore(stdinFd, oldState)

		resize := make(chan backend.TermSize, 1)
		stream.Resize = resize

		// Prime with the current size, then follow SIGWINCH.
		sendSize(resize)
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for range winch {
				sendSize(resize)
			}
		}()
	}

	return be.AttachPTY(ctx, id, stream)
}

func sendSize(ch chan<- backend.TermSize) {
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return
	}
	select {
	case ch <- backend.TermSize{Rows: uint16(rows), Cols: uint16(cols)}:
	default:
	}
}
