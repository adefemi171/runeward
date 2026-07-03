// Package controller reconciles runeward Sandbox and Fleet custom resources
// onto the control-plane Manager.
//
// It deliberately avoids controller-runtime: dynamic informers feed a work
// queue, backing runeward ids live in status, and a finalizer guarantees
// teardown of the underlying sandboxes/fleets on CR deletion.
package controller

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/adefemi171/runeward/internal/controlplane"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	// Group is the API group of the runeward CRDs.
	Group = "runeward.dev"
	// Version is the CRD API version.
	Version = "v1alpha1"
	// finalizer blocks CR deletion until the backing resource is torn down.
	finalizer = "runeward.dev/finalizer"
)

var (
	sandboxGVR = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "sandboxes"}
	fleetGVR   = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "fleets"}
	// Cluster-scoped variants carry no namespace; backing resources land in
	// the controller's own namespace.
	clusterSandboxGVR = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "clustersandboxes"}
	clusterFleetGVR   = schema.GroupVersionResource{Group: Group, Version: Version, Resource: "clusterfleets"}
)

var clusterScoped = map[schema.GroupVersionResource]bool{
	clusterSandboxGVR: true,
	clusterFleetGVR:   true,
}

// item identifies one custom resource on the work queue.
type item struct {
	gvr schema.GroupVersionResource
	key string // "namespace/name"
}

// Controller reconciles runeward CRs against a control-plane Manager.
type Controller struct {
	mgr *controlplane.Manager
	dyn dynamic.Interface
	// factory watches namespaced CRs in the configured namespace;
	// clusterFactory watches the cluster-scoped ones cluster-wide.
	factory        dynamicinformer.DynamicSharedInformerFactory
	clusterFactory dynamicinformer.DynamicSharedInformerFactory
	queue          workqueue.TypedRateLimitingInterface[item]
	logger         *log.Logger
}

// New builds a Controller watching the given namespace ("" for all).
func New(mgr *controlplane.Manager, dyn dynamic.Interface, namespace string, logger *log.Logger) *Controller {
	if logger == nil {
		logger = log.Default()
	}
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dyn, 10*time.Minute, namespace, nil)
	clusterFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dyn, 10*time.Minute, metav1.NamespaceAll, nil)
	c := &Controller{
		mgr:            mgr,
		dyn:            dyn,
		factory:        factory,
		clusterFactory: clusterFactory,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[item](),
			workqueue.TypedRateLimitingQueueConfig[item]{Name: "runeward"},
		),
		logger: logger,
	}
	c.addInformer(factory, sandboxGVR)
	c.addInformer(factory, fleetGVR)
	c.addInformer(clusterFactory, clusterSandboxGVR)
	c.addInformer(clusterFactory, clusterFleetGVR)
	return c
}

func (c *Controller) addInformer(factory dynamicinformer.DynamicSharedInformerFactory, gvr schema.GroupVersionResource) {
	inf := factory.ForResource(gvr).Informer()
	enqueue := func(obj any) {
		if key, err := cache.MetaNamespaceKeyFunc(obj); err == nil {
			c.queue.Add(item{gvr: gvr, key: key})
		}
	}
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    enqueue,
		UpdateFunc: func(_, obj any) { enqueue(obj) },
		DeleteFunc: enqueue,
	})
}

// Run starts the informers and reconcile workers, blocking until ctx is done.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer c.queue.ShutDown()

	c.factory.Start(ctx.Done())
	c.clusterFactory.Start(ctx.Done())
	c.logger.Printf("controller: syncing caches for %s", Group)
	for gvr, ok := range c.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("failed to sync cache for %s", gvr)
		}
	}
	for gvr, ok := range c.clusterFactory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("failed to sync cache for %s", gvr)
		}
	}
	c.logger.Printf("controller: caches synced, starting %d workers", workers)

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	<-ctx.Done()
	c.logger.Printf("controller: shutting down")
	return nil
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *Controller) processNext(ctx context.Context) bool {
	it, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(it)

	if err := c.reconcile(ctx, it); err != nil {
		c.logger.Printf("controller: reconcile %s %s: %v (requeue)", it.gvr.Resource, it.key, err)
		c.queue.AddRateLimited(it)
		return true
	}
	c.queue.Forget(it)
	return true
}

func (c *Controller) reconcile(ctx context.Context, it item) error {
	ns, name, err := cache.SplitMetaNamespaceKey(it.key)
	if err != nil {
		return err
	}
	// Cluster-scoped resources must not be namespaced on the dynamic client.
	var client dynamic.ResourceInterface
	if clusterScoped[it.gvr] {
		client = c.dyn.Resource(it.gvr)
	} else {
		client = c.dyn.Resource(it.gvr).Namespace(ns)
	}

	obj, err := client.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// Deleted and already finalized; nothing to do.
		return nil
	}

	// Handle deletion: tear down the backing resource, then drop the finalizer.
	if obj.GetDeletionTimestamp() != nil {
		if !hasFinalizer(obj) {
			return nil
		}
		if err := c.teardown(ctx, it.gvr, obj); err != nil {
			return err
		}
		removeFinalizer(obj)
		_, err := client.Update(ctx, obj, metav1.UpdateOptions{})
		return err
	}

	// Ensure the finalizer is present before we create anything.
	if !hasFinalizer(obj) {
		addFinalizer(obj)
		updated, err := client.Update(ctx, obj, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		obj = updated
	}

	switch it.gvr {
	case sandboxGVR, clusterSandboxGVR:
		return c.reconcileSandbox(ctx, client, obj)
	case fleetGVR, clusterFleetGVR:
		return c.reconcileFleet(ctx, client, obj)
	default:
		return nil
	}
}

func (c *Controller) reconcileSandbox(ctx context.Context, client dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
	if id, _, _ := unstructured.NestedString(obj.Object, "status", "sandboxId"); id != "" {
		// Already provisioned; verify it still exists in the manager.
		if _, ok := c.mgr.Sandbox(id); ok {
			return nil
		}
		// Backing sandbox vanished (e.g. controller restart); reprovision.
	}

	profileName, _, _ := unstructured.NestedString(obj.Object, "spec", "profile")
	if profileName == "" {
		return c.setStatus(ctx, client, obj, map[string]any{
			"phase": "Failed", "message": "spec.profile is required",
		})
	}

	sb, err := c.mgr.CreateSandbox(ctx, profileName, controlplane.CreateOptions{})
	if err != nil {
		return c.setStatus(ctx, client, obj, map[string]any{
			"phase": "Failed", "message": err.Error(),
		})
	}
	c.logger.Printf("controller: sandbox %s/%s -> %s", obj.GetNamespace(), obj.GetName(), sb.ID)
	return c.setStatus(ctx, client, obj, map[string]any{
		"phase":     "Running",
		"sandboxId": sb.ID,
		"backend":   sb.Backend,
		"image":     sb.Image,
		"message":   "",
	})
}

func (c *Controller) reconcileFleet(ctx context.Context, client dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
	fid, _, _ := unstructured.NestedString(obj.Object, "status", "fleetId")
	if fid != "" {
		if v, ok := c.mgr.FleetView(fid); ok {
			return c.setStatus(ctx, client, obj, fleetStatus("Running", v))
		}
		// Fleet gone; recreate below.
	}

	profileName, _, _ := unstructured.NestedString(obj.Object, "spec", "profile")
	if profileName == "" {
		return c.setStatus(ctx, client, obj, map[string]any{
			"phase": "Failed", "message": "spec.profile is required",
		})
	}

	v, err := c.mgr.CreateFleet(ctx, profileName)
	if err != nil {
		return c.setStatus(ctx, client, obj, map[string]any{
			"phase": "Failed", "message": err.Error(),
		})
	}
	c.logger.Printf("controller: fleet %s/%s -> %s (%d sandboxes)", obj.GetNamespace(), obj.GetName(), v.ID, len(v.Sandboxes))
	return c.setStatus(ctx, client, obj, fleetStatus("Running", v))
}

// teardown removes the backing sandbox or fleet for a CR being deleted.
func (c *Controller) teardown(ctx context.Context, gvr schema.GroupVersionResource, obj *unstructured.Unstructured) error {
	switch gvr {
	case sandboxGVR, clusterSandboxGVR:
		if id, _, _ := unstructured.NestedString(obj.Object, "status", "sandboxId"); id != "" {
			if err := c.mgr.KillSandbox(ctx, id); err != nil {
				c.logger.Printf("controller: kill sandbox %s: %v (continuing)", id, err)
			}
		}
	case fleetGVR, clusterFleetGVR:
		if id, _, _ := unstructured.NestedString(obj.Object, "status", "fleetId"); id != "" {
			if err := c.mgr.KillFleet(ctx, id); err != nil {
				c.logger.Printf("controller: kill fleet %s: %v (continuing)", id, err)
			}
		}
	}
	return nil
}

// setStatus writes the merged status subresource, stamping observedGeneration.
func (c *Controller) setStatus(ctx context.Context, client dynamic.ResourceInterface, obj *unstructured.Unstructured, status map[string]any) error {
	cur, _, _ := unstructured.NestedMap(obj.Object, "status")
	if cur == nil {
		cur = map[string]any{}
	}
	for k, v := range status {
		cur[k] = v
	}
	cur["observedGeneration"] = obj.GetGeneration()
	if err := unstructured.SetNestedMap(obj.Object, cur, "status"); err != nil {
		return err
	}
	_, err := client.UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}

func fleetStatus(phase string, v *controlplane.FleetView) map[string]any {
	sandboxes := make([]any, len(v.Sandboxes))
	for i, s := range v.Sandboxes {
		sandboxes[i] = s
	}
	return map[string]any{
		"phase":        phase,
		"fleetId":      v.ID,
		"sandboxes":    sandboxes,
		"tasksTotal":   int64(v.Stats.Total),
		"tasksPending": int64(v.Stats.Pending),
		"tasksClaimed": int64(v.Stats.Claimed),
		"tasksDone":    int64(v.Stats.Done),
		"tasksFailed":  int64(v.Stats.Failed),
		"message":      "",
	}
}

func hasFinalizer(obj *unstructured.Unstructured) bool {
	for _, f := range obj.GetFinalizers() {
		if f == finalizer {
			return true
		}
	}
	return false
}

func addFinalizer(obj *unstructured.Unstructured) {
	obj.SetFinalizers(append(obj.GetFinalizers(), finalizer))
}

func removeFinalizer(obj *unstructured.Unstructured) {
	out := obj.GetFinalizers()[:0]
	for _, f := range obj.GetFinalizers() {
		if f != finalizer {
			out = append(out, f)
		}
	}
	obj.SetFinalizers(out)
}
