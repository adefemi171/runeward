package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adefemi171/runeward/internal/webhook"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// newWebhookCmd runs the admission webhook enforcing ClusterPolicy on Sandbox
// and Fleet CRs. It self-registers its webhook configurations at startup with
// a self-signed cert whose CA goes into the caBundle.
func newWebhookCmd(configDir *string) *cobra.Command {
	_ = configDir // profiles are not resolved by the webhook; kept for symmetry.
	var port int
	var service string
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Enforce runeward ClusterPolicy on Sandbox/Fleet (admission webhook)",
		Long: "Serve a validating+mutating admission webhook that applies\n" +
			"runeward.dev/v1alpha1 ClusterPolicy defaults and guardrails to Sandbox\n" +
			"and Fleet resources. Apply the ClusterPolicy CRD first (or use\n" +
			"`runeward up`). The webhook self-registers its configurations and serves\n" +
			"HTTPS with a self-signed certificate it mints on startup.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := kubeConfig()
			if err != nil {
				return err
			}
			clientset, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("build clientset: %w", err)
			}
			dyn, err := dynamic.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("build dynamic client: %w", err)
			}

			ns := kubeNamespace()
			if service == "" {
				service = "runeward-webhook"
			}
			dnsNames := []string{
				fmt.Sprintf("%s.%s.svc", service, ns),
				fmt.Sprintf("%s.%s.svc.cluster.local", service, ns),
			}

			certPEM, keyPEM, caPEM, err := webhook.GenerateCert(dnsNames)
			if err != nil {
				return fmt.Errorf("generate serving certificate: %w", err)
			}
			keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("load serving certificate: %w", err)
			}

			logger := log.New(os.Stderr, "runeward-webhook ", log.LstdFlags|log.LUTC)

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if err := webhook.Register(ctx, clientset, caPEM, service, ns); err != nil {
				return fmt.Errorf("register webhook configurations: %w", err)
			}

			srv := webhook.NewServer(dyn, logger)
			httpSrv := &http.Server{
				Addr:      fmt.Sprintf(":%d", port),
				Handler:   srv.Handler(),
				TLSConfig: &tls.Config{Certificates: []tls.Certificate{keyPair}, MinVersion: tls.VersionTLS12},
			}

			errCh := make(chan error, 1)
			go func() {
				logger.Printf("starting webhook (service=%s.%s, port=%d)", service, ns, port)
				if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			select {
			case err := <-errCh:
				return fmt.Errorf("serve webhook: %w", err)
			case <-ctx.Done():
				logger.Printf("webhook: shutting down")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return httpSrv.Shutdown(shutdownCtx)
			}
		},
	}
	cmd.Flags().IntVar(&port, "port", 8443, "HTTPS port to serve admission requests on")
	cmd.Flags().StringVar(&service, "service", os.Getenv("RUNEWARD_WEBHOOK_SERVICE"),
		"name of the Service fronting the webhook (or $RUNEWARD_WEBHOOK_SERVICE)")
	return cmd
}
