package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/adefemi171/runeward/internal/manifests"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
)

// fieldManager is the server-side-apply owner for everything we apply.
const fieldManager = "runeward-up"

// newUpCmd installs the CRDs and controller bundle via server-side apply, so
// re-running it is idempotent.
func newUpCmd() *cobra.Command {
	var image string
	var crdsOnly bool
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Install runeward (CRDs + controller) into the current cluster",
		Long: "One-command install: applies the runeward CRDs and, unless --crds-only,\n" +
			"the controller bundle (namespace, RBAC, Deployment) via server-side apply.\n" +
			"Idempotent — safe to re-run to upgrade. Uses the ambient kubeconfig.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if image == "" {
				image = os.Getenv("RUNEWARD_IMAGE")
			}
			cfg, err := kubeConfig()
			if err != nil {
				return err
			}
			dyn, err := dynamic.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("build dynamic client: %w", err)
			}
			disco, err := discovery.NewDiscoveryClientForConfig(cfg)
			if err != nil {
				return fmt.Errorf("build discovery client: %w", err)
			}
			mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disco))
			out := cmd.OutOrStdout()

			crds, err := manifests.CRDs()
			if err != nil {
				return err
			}
			for _, doc := range crds {
				if err := applyDoc(cmd.Context(), dyn, mapper, doc, "", out); err != nil {
					return err
				}
			}
			// Reset the cached mapper so discovery sees the fresh CRDs before
			// any custom resources get applied.
			mapper.Reset()

			if crdsOnly {
				fmt.Fprintln(out, "runeward: CRDs installed. Run the controller with `runeward controller`.")
				return nil
			}

			install, err := manifests.Install()
			if err != nil {
				return err
			}
			for _, doc := range install {
				if err := applyDoc(cmd.Context(), dyn, mapper, doc, image, out); err != nil {
					return err
				}
			}
			fmt.Fprintln(out, "runeward: installed. Add profiles with a ConfigMap named 'runeward-profiles', e.g.:")
			fmt.Fprintln(out, "  kubectl -n runeward create configmap runeward-profiles --from-file=examples/")
			return nil
		},
	}
	cmd.Flags().StringVar(&image, "image", "", "controller image (or $RUNEWARD_IMAGE); defaults to runeward:latest")
	cmd.Flags().BoolVar(&crdsOnly, "crds-only", false, "install only the CRDs, not the controller")
	return cmd
}

// applyDoc decodes one YAML document and server-side-applies it, optionally
// overriding container images.
func applyDoc(ctx context.Context, dyn dynamic.Interface, mapper *restmapper.DeferredDiscoveryRESTMapper, doc []byte, imageOverride string, out io.Writer) error {
	if len(bytes.TrimSpace(doc)) == 0 {
		return nil
	}
	obj := &unstructured.Unstructured{}
	if err := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), 4096).Decode(obj); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if obj.GetKind() == "" {
		return nil
	}
	if imageOverride != "" {
		overrideImages(obj, imageOverride)
	}

	gvk := obj.GroupVersionKind()
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("map %s: %w", gvk, err)
	}

	var ri dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = kubeNamespace()
			obj.SetNamespace(ns)
		}
		ri = dyn.Resource(mapping.Resource).Namespace(ns)
	} else {
		ri = dyn.Resource(mapping.Resource)
	}

	data, err := obj.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = ri.Patch(ctx, obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
		FieldManager: fieldManager,
		Force:        boolPtr(true),
	})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("apply %s %s: %w", obj.GetKind(), obj.GetName(), err)
	}
	fmt.Fprintf(out, "  applied %s/%s\n", strings.ToLower(obj.GetKind()), obj.GetName())
	return nil
}

func boolPtr(b bool) *bool { return &b }

// overrideImages sets every container and initContainer image to img.
func overrideImages(obj *unstructured.Unstructured, img string) {
	for _, path := range [][]string{
		{"spec", "template", "spec", "containers"},
		{"spec", "template", "spec", "initContainers"},
	} {
		list, found, err := unstructured.NestedSlice(obj.Object, path...)
		if err != nil || !found {
			continue
		}
		for i := range list {
			if c, ok := list[i].(map[string]any); ok {
				c["image"] = img
			}
		}
		_ = unstructured.SetNestedSlice(obj.Object, list, path...)
	}
}
