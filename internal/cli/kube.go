package cli

import (
	"fmt"
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubeConfig prefers the in-cluster config and falls back to the ambient
// kubeconfig; $RUNEWARD_KUBE_CONTEXT pins the context.
func kubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if kctx := os.Getenv("RUNEWARD_KUBE_CONTEXT"); kctx != "" {
		overrides.CurrentContext = kctx
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return cfg, nil
}

func kubeNamespace() string {
	if ns := os.Getenv("RUNEWARD_K8S_NAMESPACE"); ns != "" {
		return ns
	}
	return "runeward"
}
