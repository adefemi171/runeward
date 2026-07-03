package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adefemi171/runeward/internal/policybundle"
	"github.com/spf13/cobra"
)

// newBundleCmd provides sign/publish/fetch tooling for OCI policy bundles.
func newBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Sign, publish, and fetch signed OCI policy bundles",
	}
	cmd.AddCommand(newBundleKeygenCmd(), newBundlePushCmd(), newBundlePullCmd())
	return cmd
}

func newBundleKeygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an ed25519 keypair for signing policy bundles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			pubB64 := policybundle.EncodeKey(pub)
			privB64 := policybundle.EncodeKey(priv)
			keyID := policybundle.KeyID(pub)

			if out == "" {
				w := cmd.OutOrStdout()
				fmt.Fprintf(w, "key-id:      %s\n", keyID)
				fmt.Fprintf(w, "public-key:  %s\n", pubB64)
				fmt.Fprintf(w, "private-key: %s\n", privB64)
				return nil
			}
			if err := os.MkdirAll(out, 0o700); err != nil {
				return err
			}
			keyPath := filepath.Join(out, "bundle.key")
			pubPath := filepath.Join(out, "bundle.pub")
			// Both halves are base64 so `bundle push --key` and profile
			// verify_key can consume them directly.
			if err := os.WriteFile(keyPath, []byte(privB64+"\n"), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "key-id:     %s\nprivate:    %s\npublic:     %s\npublic-key: %s\n", keyID, keyPath, pubPath, pubB64)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "write bundle.key (0600) and bundle.pub to this directory instead of stdout")
	return cmd
}

func newBundlePushCmd() *cobra.Command {
	var (
		policyFile string
		engine     string
		query      string
		keyFile    string
		plainHTTP  bool
	)
	cmd := &cobra.Command{
		Use:   "push <ref>",
		Short: "Push a signed policy bundle to an OCI registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch engine {
			case policybundle.EngineRego, policybundle.EngineCEL:
			default:
				return fmt.Errorf("--engine must be %q or %q, got %q", policybundle.EngineRego, policybundle.EngineCEL, engine)
			}
			if policyFile == "" {
				return fmt.Errorf("--policy is required")
			}
			if keyFile == "" {
				return fmt.Errorf("--key is required")
			}
			policyBytes, err := os.ReadFile(policyFile)
			if err != nil {
				return fmt.Errorf("read policy: %w", err)
			}
			priv, err := loadPrivateKey(keyFile)
			if err != nil {
				return err
			}
			b := &policybundle.Bundle{Engine: engine, Query: query, Policy: policyBytes}

			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			digest, err := policybundle.Push(ctx, args[0], b, priv, policybundle.PushOptions{PlainHTTP: plainHTTP})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "pushed %s\ndigest: %s\n", policybundle.StripScheme(args[0]), digest)
			return nil
		},
	}
	cmd.Flags().StringVar(&policyFile, "policy", "", "path to the policy file (.rego module, or TOML fragment with [[cel]] rules)")
	cmd.Flags().StringVar(&engine, "engine", "", "policy engine: rego or cel")
	cmd.Flags().StringVar(&query, "query", "", "optional Rego decision query (rego only)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to a base64 ed25519 private key file (from `bundle keygen`)")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "use http instead of https (local/insecure registries)")
	return cmd
}

func newBundlePullCmd() *cobra.Command {
	var (
		verifyKey string
		plainHTTP bool
		out       string
	)
	cmd := &cobra.Command{
		Use:   "pull <ref>",
		Short: "Pull (and optionally verify) a signed policy bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var verify ed25519.PublicKey
			if verifyKey != "" {
				k, err := loadPublicKey(verifyKey)
				if err != nil {
					return err
				}
				verify = k
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			b, err := policybundle.Pull(ctx, args[0], verify, policybundle.PullOptions{PlainHTTP: plainHTTP})
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			verified := "no (no verify key supplied)"
			if verify != nil {
				verified = "yes"
			}
			fmt.Fprintf(w, "engine:   %s\n", b.Engine)
			if b.Query != "" {
				fmt.Fprintf(w, "query:    %s\n", b.Query)
			}
			fmt.Fprintf(w, "verified: %s\n", verified)
			if out != "" {
				if err := os.WriteFile(out, b.Policy, 0o644); err != nil {
					return err
				}
				fmt.Fprintf(w, "policy written to %s (%d bytes)\n", out, len(b.Policy))
				return nil
			}
			fmt.Fprintf(w, "policy:\n%s\n", string(b.Policy))
			return nil
		},
	}
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "base64 ed25519 public key (or a path to a file containing one); when set the signature is required")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "use http instead of https (local/insecure registries)")
	cmd.Flags().StringVar(&out, "out", "", "write the raw policy to this file instead of printing it")
	return cmd
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return policybundle.DecodePrivateKey(strings.TrimSpace(string(b)))
}

// loadPublicKey accepts an inline base64 key or a path to a file containing one.
func loadPublicKey(keyOrPath string) (ed25519.PublicKey, error) {
	val := strings.TrimSpace(keyOrPath)
	if b, err := os.ReadFile(val); err == nil {
		val = strings.TrimSpace(string(b))
	}
	return policybundle.DecodePublicKey(val)
}
