package backend

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Detect returns the backend hosting sandbox id, probing Docker then
// Kubernetes. A backend that can't be constructed (e.g. no kubeconfig) is
// skipped, not an error.
func Detect(ctx context.Context, id string) (Backend, error) {
	if d, err := NewDocker(); err == nil && d.has(ctx, id) {
		return d, nil
	}
	if k, err := NewK8s(); err == nil && k.has(ctx, id) {
		return k, nil
	}
	return nil, fmt.Errorf("sandbox %q not found (looked in docker and kubernetes)", id)
}

// Export copies the workspace of sandbox id to destDir on the host. It's a
// point-in-time copy; later host edits never flow back into the sandbox.
func Export(ctx context.Context, id, destDir string) error {
	be, err := Detect(ctx, id)
	if err != nil {
		return err
	}
	// Absolute + cleaned so the tar-extraction containment checks are reliable.
	if abs, err := filepath.Abs(destDir); err == nil {
		destDir = abs
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("export: create destination %q: %w", destDir, err)
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(be.ExportWorkspace(ctx, id, pw))
	}()
	if err := extractTar(pr, destDir); err != nil {
		_ = pr.CloseWithError(err)
		return err
	}
	return nil
}
