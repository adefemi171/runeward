package manifests

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedManifestsLoad(t *testing.T) {
	crds, err := CRDs()
	if err != nil {
		t.Fatalf("CRDs: %v", err)
	}
	if len(crds) != 5 {
		t.Fatalf("expected 5 CRDs, got %d", len(crds))
	}
	install, err := Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(install) < 3 {
		t.Fatalf("expected >=3 install docs, got %d", len(install))
	}
}

// Guards against drift between the embedded CRDs and the deploy/ copies.
func TestCRDCopiesInSync(t *testing.T) {
	for _, name := range []string{
		"runeward.dev_sandboxes.yaml",
		"runeward.dev_fleets.yaml",
		"runeward.dev_clusterpolicies.yaml",
		"runeward.dev_clustersandboxes.yaml",
		"runeward.dev_clusterfleets.yaml",
	} {
		canonical, err := files.ReadFile("crds/" + name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		for _, copyDir := range []string{
			"../../deploy/crds",
			"../../deploy/helm/runeward/crds",
		} {
			p := filepath.Join(copyDir, name)
			got, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			if string(got) != string(canonical) {
				t.Errorf("%s differs from embedded canonical crds/%s; run: cp internal/manifests/crds/%s %s/",
					p, name, name, copyDir)
			}
		}
	}
}
