package cli

import (
	"fmt"
	"os"

	"github.com/adefemi171/runeward/internal/ledger"
	"github.com/spf13/cobra"
)

// newAuditCmd provides offline audit tools. Verification needs no running
// control plane; the exported bundle embeds the public key.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Offline audit tools (verify exported transcript bundles)",
	}
	cmd.AddCommand(newAuditVerifyCmd())
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <bundle.json>",
		Short: "Verify an exported, signed audit transcript bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			n, err := ledger.VerifyBundle(f)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok: %d events verified (hash chain + signatures intact)\n", n)
			return nil
		},
	}
}
