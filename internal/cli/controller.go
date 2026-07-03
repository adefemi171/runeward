package cli

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/adefemi171/runeward/internal/controller"
	"github.com/adefemi171/runeward/internal/controlplane"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
)

// newControllerCmd runs the Kubernetes controller that reconciles Sandbox and
// Fleet CRs onto the control-plane Manager.
func newControllerCmd(configDir *string) *cobra.Command {
	var workers int
	var allNamespaces bool
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Reconcile runeward Sandbox/Fleet custom resources (Kubernetes)",
		Long: "Watch runeward.dev/v1alpha1 Sandbox and Fleet resources and reconcile\n" +
			"them onto the governed Kubernetes backend. Apply the CRDs from deploy/crds\n" +
			"first (or use `runeward up`). Profiles are resolved from --config-dir /\n" +
			"$RUNEWARD_CONFIG_DIR, typically a mounted ConfigMap in-cluster.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := kubeConfig()
			if err != nil {
				return err
			}
			dyn, err := dynamic.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("build dynamic client: %w", err)
			}

			mgr, err := controlplane.New(resolveConfigDir(*configDir))
			if err != nil {
				return err
			}
			defer mgr.Close()

			ns := kubeNamespace()
			if allNamespaces {
				ns = ""
			}
			logger := log.New(os.Stderr, "runeward-controller ", log.LstdFlags|log.LUTC)
			ctrl := controller.New(mgr, dyn, ns, logger)

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			scope := ns
			if scope == "" {
				scope = "all namespaces"
			}
			logger.Printf("starting controller (scope=%s, workers=%d)", scope, workers)
			return ctrl.Run(ctx, workers)
		},
	}
	cmd.Flags().IntVar(&workers, "workers", 2, "number of reconcile workers")
	cmd.Flags().BoolVar(&allNamespaces, "all-namespaces", false, "watch all namespaces instead of $RUNEWARD_K8S_NAMESPACE")
	return cmd
}
