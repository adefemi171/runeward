package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Runewardd/runeward/internal/egress"
	"github.com/Runewardd/runeward/internal/profile"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

// k8sContainer is the fixed name of the sandbox container within each pod.
const k8sContainer = "sandbox"

// K8s provisions one Pod (plus a workspace PVC) per sandbox via client-go,
// managing Pods directly rather than through a controller.
type K8s struct {
	client    kubernetes.Interface
	rest      *rest.Config
	namespace string
}

// NewK8s builds the Kubernetes backend from the ambient kubeconfig.
// $RUNEWARD_KUBE_CONTEXT pins the context; $RUNEWARD_K8S_NAMESPACE overrides
// the default "runeward" namespace.
func NewK8s() (*K8s, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if kctx := os.Getenv("RUNEWARD_KUBE_CONTEXT"); kctx != "" {
		overrides.CurrentContext = kctx
	}
	cfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	restCfg, err := cfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	ns := os.Getenv("RUNEWARD_K8S_NAMESPACE")
	if ns == "" {
		ns = "runeward"
	}
	return &K8s{client: client, rest: restCfg, namespace: ns}, nil
}

func (k *K8s) Name() string { return "k8s" }

func (k *K8s) Create(ctx context.Context, spec Spec) (*Sandbox, error) {
	if err := k.ensureNamespace(ctx); err != nil {
		return nil, err
	}
	if err := k.ensureNetworkPolicy(ctx); err != nil {
		return nil, err
	}
	id := newID()
	podName := containerName(id)
	pvcName := volumeName(id)
	workdir := spec.Workdir
	if workdir == "" {
		workdir = "/workspace"
	}
	image := spec.Image
	if image == "" {
		image = "debian:stable-slim"
	}

	labels := map[string]string{
		labelKey(labelManaged): "true",
		labelKey(labelProfile): spec.Profile,
		labelKey(labelID):      id,
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName, Labels: labels},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("2Gi")},
			},
		},
	}
	if _, err := k.client.CoreV1().PersistentVolumeClaims(k.namespace).Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("create workspace pvc: %w", err)
	}

	env := make([]corev1.EnvVar, 0, len(spec.Env))
	for name, val := range spec.Env {
		env = append(env, corev1.EnvVar{Name: name, Value: val})
	}

	resources := corev1.ResourceRequirements{Limits: corev1.ResourceList{}}
	if spec.Resources.MemoryBytes > 0 {
		resources.Limits[corev1.ResourceMemory] = *resource.NewQuantity(spec.Resources.MemoryBytes, resource.BinarySI)
	}
	if spec.Resources.NanoCPUs > 0 {
		resources.Limits[corev1.ResourceCPU] = *resource.NewMilliQuantity(spec.Resources.NanoCPUs/1_000_000, resource.DecimalSI)
	}

	// Deny-by-default profiles get an egress-proxy sidecar; the policy arrives
	// via a mounted ConfigMap. Cooperative mode (default) points the sandbox at
	// the proxy with HTTP(S)_PROXY, which an app can ignore. Strict mode adds an
	// iptables init container that redirects all egress, so it can't be bypassed.
	var extraContainers []corev1.Container
	var extraInit []corev1.Container
	var extraVolumes []corev1.Volume
	if spec.Network.DenyByDefault() {
		polJSON, err := json.Marshal(policyFromNetwork(spec.Network))
		if err != nil {
			_ = k.client.CoreV1().PersistentVolumeClaims(k.namespace).Delete(context.Background(), pvcName, metav1.DeleteOptions{})
			return nil, fmt.Errorf("marshal egress policy: %w", err)
		}
		cmName := egressConfigMapName(id)
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: cmName, Labels: labels},
			Data:       map[string]string{"policy.json": string(polJSON)},
		}
		if _, err := k.client.CoreV1().ConfigMaps(k.namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			_ = k.client.CoreV1().PersistentVolumeClaims(k.namespace).Delete(context.Background(), pvcName, metav1.DeleteOptions{})
			return nil, fmt.Errorf("create egress configmap: %w", err)
		}
		img := os.Getenv("RUNEWARD_EGRESS_IMAGE")
		if img == "" {
			img = "runeward-egress:latest"
		}
		policyMount := corev1.VolumeMount{
			Name:      "egress-policy",
			MountPath: "/etc/runeward",
			ReadOnly:  true,
		}

		if spec.Network.StrictEgress() {
			redirectPort := strconv.Itoa(egress.StrictRedirectPort)
			proxyUID := int64(egress.StrictProxyUID)
			// Installs the iptables REDIRECT rules; needs NET_ADMIN.
			extraInit = append(extraInit, corev1.Container{
				Name:            "egress-init",
				Image:           img,
				ImagePullPolicy: egressPullPolicy(img),
				Args: []string{
					"--setup-iptables",
					"--proxy-uid", strconv.FormatInt(proxyUID, 10),
					"--redirect-port", redirectPort,
				},
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:    int64Ptr(0),
					Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"}},
				},
			})
			// Runs as the exempt uid so its own upstream traffic isn't
			// redirected back to itself.
			extraContainers = append(extraContainers, corev1.Container{
				Name:            "egress",
				Image:           img,
				ImagePullPolicy: egressPullPolicy(img),
				Args:            []string{"--transparent", "--redirect-port", redirectPort, "--policy", "/etc/runeward/policy.json"},
				SecurityContext: &corev1.SecurityContext{RunAsUser: int64Ptr(proxyUID)},
				VolumeMounts:    []corev1.VolumeMount{policyMount},
			})
			// No HTTP(S)_PROXY env; enforcement is transparent at L3.
		} else {
			extraContainers = append(extraContainers, corev1.Container{
				Name:            "egress",
				Image:           img,
				ImagePullPolicy: egressPullPolicy(img),
				// Bind loopback: sidecar and sandbox share the pod netns, so the
				// sandbox reaches it via localhost:8888, but nothing off-pod can.
				Args:         []string{"--addr", "127.0.0.1:8888", "--policy", "/etc/runeward/policy.json"},
				VolumeMounts: []corev1.VolumeMount{policyMount},
			})
			for name, val := range proxyEnv("http://localhost:8888") {
				env = append(env, corev1.EnvVar{Name: name, Value: val})
			}
		}

		extraVolumes = append(extraVolumes, corev1.Volume{
			Name: "egress-policy",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: cmName},
				},
			},
		})
	}

	sandboxMounts := []corev1.VolumeMount{{
		Name:      "workspace",
		MountPath: workdir,
	}}
	var sandboxSecCtx *corev1.SecurityContext
	if spec.ReadOnly {
		sandboxSecCtx = &corev1.SecurityContext{ReadOnlyRootFilesystem: boolPtr(true)}
		sandboxMounts = append(sandboxMounts, corev1.VolumeMount{Name: "tmp", MountPath: "/tmp"})
		extraVolumes = append(extraVolumes, corev1.Volume{
			Name:         "tmp",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
	}
	if spec.AppArmor != "" {
		if sandboxSecCtx == nil {
			sandboxSecCtx = &corev1.SecurityContext{}
		}
		sandboxSecCtx.AppArmorProfile = appArmorProfile(spec.AppArmor)
	}
	// Always harden the sandbox container itself (not the egress sidecar/init,
	// which need NET_ADMIN/NET_RAW). Mirrors the docker backend's --cap-drop ALL
	// + --security-opt no-new-privileges. RunAsNonRoot is deliberately left
	// unset because arbitrary sandbox images may legitimately need to run as root.
	if sandboxSecCtx == nil {
		sandboxSecCtx = &corev1.SecurityContext{}
	}
	sandboxSecCtx.AllowPrivilegeEscalation = boolPtr(false)
	sandboxSecCtx.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}

	// Default to the runtime's seccomp profile (rather than Unconfined) and
	// allow a profile to pin a stricter Localhost seccomp profile.
	podSecCtx := &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if spec.Seccomp != "" {
		profilePath := spec.Seccomp
		podSecCtx.SeccompProfile = &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &profilePath,
		}
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:      corev1.RestartPolicyAlways,
			RuntimeClassName:   runtimeClassPtr(spec.RuntimeClass),
			EnableServiceLinks: boolPtr(false),
			SecurityContext:    podSecCtx,
			InitContainers:     extraInit,
			Containers: []corev1.Container{{
				Name:            k8sContainer,
				Image:           image,
				Command:         []string{"sleep", "infinity"},
				WorkingDir:      workdir,
				Env:             env,
				Resources:       resources,
				SecurityContext: sandboxSecCtx,
				VolumeMounts:    sandboxMounts,
			}},
			Volumes: []corev1.Volume{{
				Name: "workspace",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName},
				},
			}},
		},
	}
	pod.Spec.Containers = append(pod.Spec.Containers, extraContainers...)
	pod.Spec.Volumes = append(pod.Spec.Volumes, extraVolumes...)
	if _, err := k.client.CoreV1().Pods(k.namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		_ = k.client.CoreV1().PersistentVolumeClaims(k.namespace).Delete(context.Background(), pvcName, metav1.DeleteOptions{})
		_ = k.client.CoreV1().ConfigMaps(k.namespace).Delete(context.Background(), egressConfigMapName(id), metav1.DeleteOptions{})
		return nil, fmt.Errorf("create pod: %w", err)
	}

	if err := k.waitRunning(ctx, podName, 90*time.Second); err != nil {
		_ = k.Kill(context.Background(), id)
		return nil, err
	}

	if spec.SeedDir != "" {
		if err := k.seedWorkspace(ctx, id, workdir, spec.SeedDir); err != nil {
			_ = k.Kill(context.Background(), id)
			return nil, err
		}
	}

	if len(spec.Files) > 0 {
		if err := k.CopyFiles(ctx, id, spec.Files); err != nil {
			_ = k.Kill(context.Background(), id)
			return nil, err
		}
	}

	return &Sandbox{
		ID:        id,
		Profile:   spec.Profile,
		Backend:   k.Name(),
		Image:     image,
		Status:    "running",
		CreatedAt: time.Now(),
	}, nil
}

func (k *K8s) Exec(ctx context.Context, id string, req ExecRequest) (*ExecResult, error) {
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	command := wrapCommand(req.Workdir, req.Env, req.Command)
	var stdout, stderr bytes.Buffer
	start := time.Now()
	err := k.stream(ctx, containerName(id), corev1.PodExecOptions{
		Container: k8sContainer,
		Command:   command,
		Stdout:    true,
		Stderr:    true,
	}, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})

	res := &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(start)}
	if err != nil {
		// A non-zero exit surfaces as an error carrying the code.
		if ec, ok := err.(interface{ ExitStatus() int }); ok {
			res.ExitCode = ec.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("pod exec: %w", err)
	}
	return res, nil
}

func (k *K8s) AttachPTY(ctx context.Context, id string, s PTYStream) error {
	command := s.Command
	if len(command) == 0 {
		command = []string{"/bin/sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"}
	}
	opts := corev1.PodExecOptions{
		Container: k8sContainer,
		Command:   command,
		Stdin:     s.Stdin != nil,
		Stdout:    true,
		Stderr:    !s.TTY, // with a TTY, stdout and stderr are merged
		TTY:       s.TTY,
	}
	stream := remotecommand.StreamOptions{
		Stdin:  s.Stdin,
		Stdout: s.Stdout,
		Tty:    s.TTY,
	}
	if s.Stderr != nil && !s.TTY {
		stream.Stderr = s.Stderr
	} else if !s.TTY {
		stream.Stderr = s.Stdout
	}
	if s.Resize != nil {
		stream.TerminalSizeQueue = &termSizeQueue{ch: s.Resize}
	}
	return k.stream(ctx, containerName(id), opts, stream)
}

func (k *K8s) CopyFiles(ctx context.Context, id string, files []profile.File) error {
	for _, f := range files {
		if err := validateProjectionPath(f.Path); err != nil {
			return err
		}
		if err := validateFileMode(f.Mode); err != nil {
			return err
		}
		var data []byte
		switch {
		case f.Content != "":
			data = []byte(f.Content)
		case f.File != "":
			b, err := os.ReadFile(expandHome(f.File))
			if err != nil {
				return fmt.Errorf("read projected file %q: %w", f.File, err)
			}
			data = b
		default:
			continue
		}
		mode := f.Mode
		if mode == "" {
			mode = "0444"
		}
		script := fmt.Sprintf(`set -e; mkdir -p "$(dirname "$1")"; cat > "$1"; chmod %s "$1"; chown root:root "$1" 2>/dev/null || true`, mode)
		command := []string{"sh", "-c", script, "sh", f.Path}
		var stderr bytes.Buffer
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := k.stream(cctx, containerName(id), corev1.PodExecOptions{
			Container: k8sContainer,
			Command:   command,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
		}, remotecommand.StreamOptions{Stdin: bytes.NewReader(data), Stdout: io.Discard, Stderr: &stderr})
		cancel()
		if err != nil {
			return fmt.Errorf("project file %q: %w: %s", f.Path, err, stderr.String())
		}
	}
	return nil
}

// seedWorkspace streams srcDir as a tar to `tar -xf -` in the container.
// Extraction runs as the pod's user so files end up owned by the sandbox
// user; the host directory is only read.
func (k *K8s) seedWorkspace(ctx context.Context, id, workdir, srcDir string) error {
	if fi, err := os.Stat(srcDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("copy_from %q must be an existing directory: %v", srcDir, err)
	}
	if err := validateSeedDir(srcDir); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		rawPr, rawPw := io.Pipe()
		go func() { rawPw.CloseWithError(writeDirTar(rawPw, srcDir)) }()
		pw.CloseWithError(filterTarSafe(pw, rawPr))
	}()

	var stderr bytes.Buffer
	err := k.stream(ctx, containerName(id), corev1.PodExecOptions{
		Container: k8sContainer,
		Command:   []string{"tar", "-C", workdir, "-xf", "-"},
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
	}, remotecommand.StreamOptions{Stdin: pr, Stdout: io.Discard, Stderr: &stderr})
	if err != nil {
		return fmt.Errorf("seed workspace from %q: %w: %s", srcDir, err, stderr.String())
	}
	return nil
}

// ExportWorkspace streams a tar of the pod workdir contents to w.
func (k *K8s) ExportWorkspace(ctx context.Context, id string, w io.Writer) error {
	workdir, err := k.workdir(ctx, id)
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	err = k.stream(ctx, containerName(id), corev1.PodExecOptions{
		Container: k8sContainer,
		Command:   []string{"tar", "-C", workdir, "-cf", "-", "."},
		Stdout:    true,
		Stderr:    true,
	}, remotecommand.StreamOptions{Stdout: w, Stderr: &stderr})
	if err != nil {
		return fmt.Errorf("export workspace: %w: %s", err, stderr.String())
	}
	return nil
}

// has reports whether a sandbox pod for id exists in the backend's namespace.
func (k *K8s) has(ctx context.Context, id string) bool {
	_, err := k.client.CoreV1().Pods(k.namespace).Get(ctx, containerName(id), metav1.GetOptions{})
	return err == nil
}

func (k *K8s) Snapshot(ctx context.Context, id, name string) (*SnapshotRef, error) {
	workdir, err := k.workdir(ctx, id)
	if err != nil {
		return nil, err
	}
	snapID := newID()
	loc := snapshotPath(snapID)
	out, err := os.Create(loc)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	var stderr bytes.Buffer
	err = k.stream(ctx, containerName(id), corev1.PodExecOptions{
		Container: k8sContainer,
		Command:   []string{"tar", "-C", workdir, "-cf", "-", "."},
		Stdout:    true,
		Stderr:    true,
	}, remotecommand.StreamOptions{Stdout: out, Stderr: &stderr})
	if err != nil {
		os.Remove(loc)
		return nil, fmt.Errorf("snapshot tar: %w: %s", err, stderr.String())
	}
	_ = out.Close()
	sum, err := hashFile(loc)
	if err != nil {
		os.Remove(loc)
		return nil, fmt.Errorf("snapshot hash: %w", err)
	}
	return &SnapshotRef{ID: snapID, Name: name, Backend: k.Name(), Location: loc, Sha256: sum, Created: time.Now()}, nil
}

func (k *K8s) Restore(ctx context.Context, ref SnapshotRef) (*Sandbox, error) {
	return k.RestoreWithSpec(ctx, ref, Spec{Profile: ref.Profile})
}

func (k *K8s) RestoreWithSpec(ctx context.Context, ref SnapshotRef, spec Spec) (*Sandbox, error) {
	if spec.Profile == "" {
		spec.Profile = ref.Profile
	}
	sb, err := k.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	workdir, err := k.workdir(ctx, sb.ID)
	if err != nil {
		_ = k.Kill(context.Background(), sb.ID)
		return nil, err
	}
	if err := verifySnapshot(ref); err != nil {
		_ = k.Kill(context.Background(), sb.ID)
		return nil, err
	}
	in, err := os.Open(ref.Location)
	if err != nil {
		_ = k.Kill(context.Background(), sb.ID)
		return nil, err
	}
	defer in.Close()

	// Sanitize the archive host-side to prevent tar-slip on extraction.
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(filterTarSafe(pw, in)) }()

	var stderr bytes.Buffer
	err = k.stream(ctx, containerName(sb.ID), corev1.PodExecOptions{
		Container: k8sContainer,
		Command:   []string{"tar", "-C", workdir, "-xf", "-"},
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
	}, remotecommand.StreamOptions{Stdin: pr, Stderr: &stderr})
	if err != nil {
		_ = k.Kill(context.Background(), sb.ID)
		return nil, fmt.Errorf("restore untar: %w: %s", err, stderr.String())
	}
	return sb, nil
}

func (k *K8s) Kill(ctx context.Context, id string) error {
	grace := int64(0)
	podErr := k.client.CoreV1().Pods(k.namespace).Delete(ctx, containerName(id), metav1.DeleteOptions{GracePeriodSeconds: &grace})
	_ = k.client.CoreV1().PersistentVolumeClaims(k.namespace).Delete(ctx, volumeName(id), metav1.DeleteOptions{})
	_ = k.client.CoreV1().ConfigMaps(k.namespace).Delete(ctx, egressConfigMapName(id), metav1.DeleteOptions{})
	if podErr != nil && !apierrors.IsNotFound(podErr) {
		return fmt.Errorf("delete pod: %w", podErr)
	}
	return nil
}

func (k *K8s) List(ctx context.Context) ([]Sandbox, error) {
	pods, err := k.client.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelKey(labelManaged) + "=true",
	})
	if err != nil {
		return nil, err
	}
	out := make([]Sandbox, 0, len(pods.Items))
	for _, p := range pods.Items {
		out = append(out, Sandbox{
			ID:        p.Labels[labelKey(labelID)],
			Profile:   p.Labels[labelKey(labelProfile)],
			Backend:   k.Name(),
			Image:     p.Spec.Containers[0].Image,
			Status:    string(p.Status.Phase),
			CreatedAt: p.CreationTimestamp.Time,
		})
	}
	return out, nil
}

func (k *K8s) ensureNamespace(ctx context.Context) error {
	existing, err := k.client.CoreV1().Namespaces().Get(ctx, k.namespace, metav1.GetOptions{})
	if err == nil {
		// The namespace already exists; make sure the Pod Security Admission
		// labels are present. This is best-effort: a failure to patch (e.g. RBAC
		// lacking namespace update) must not block sandbox creation.
		k.applyPSALabels(ctx, existing)
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("check namespace: %w", err)
	}
	labels := map[string]string{labelKey(labelManaged): "true"}
	for key, val := range psaLabels() {
		labels[key] = val
	}
	_, err = k.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: k.namespace, Labels: labels},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create namespace: %w", err)
	}
	return nil
}

// psaEnforceLevel returns the Pod Security Admission enforce level. It defaults
// to "privileged" because runeward's strict-egress sidecar needs NET_ADMIN,
// which the "baseline"/"restricted" levels forbid at enforcement time. Override
// via RUNEWARD_K8S_PSA_ENFORCE (privileged|baseline|restricted).
func psaEnforceLevel() string {
	switch os.Getenv("RUNEWARD_K8S_PSA_ENFORCE") {
	case "restricted":
		return "restricted"
	case "baseline":
		return "baseline"
	default:
		return "privileged"
	}
}

// psaLabels builds the Pod Security Admission labels for the managed namespace.
// enforce is overridable (see psaEnforceLevel) but warn/audit are pinned to
// "baseline" so violations are still surfaced without breaking strict egress.
func psaLabels() map[string]string {
	return map[string]string{
		"pod-security.kubernetes.io/enforce":         psaEnforceLevel(),
		"pod-security.kubernetes.io/enforce-version": "latest",
		"pod-security.kubernetes.io/warn":            "baseline",
		"pod-security.kubernetes.io/warn-version":    "latest",
		"pod-security.kubernetes.io/audit":           "baseline",
		"pod-security.kubernetes.io/audit-version":   "latest",
	}
}

// applyPSALabels patches PSA labels onto an existing namespace when any are
// missing. Best-effort: failures are logged, never fatal.
func (k *K8s) applyPSALabels(ctx context.Context, ns *corev1.Namespace) {
	desired := psaLabels()
	missing := false
	for key, val := range desired {
		if ns.Labels[key] != val {
			missing = true
			break
		}
	}
	if !missing {
		return
	}
	updated := ns.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for key, val := range desired {
		updated.Labels[key] = val
	}
	if _, err := k.client.CoreV1().Namespaces().Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		log.Printf("runeward: could not apply Pod Security Admission labels to namespace %q (non-fatal): %v", k.namespace, err)
	}
}

// ensureNetworkPolicy installs a default-deny NetworkPolicy in the managed
// namespace when RUNEWARD_K8S_NETWORK_POLICY is truthy. It is off by default:
// a default-deny policy only takes effect under a CNI that enforces
// NetworkPolicy, and could silently break connectivity for single-tenant
// users who don't expect it. When enabled it denies all ingress and allows
// egress only to DNS (UDP+TCP 53); actual egress allowlisting is handled by
// runeward's own L3 egress proxy.
func (k *K8s) ensureNetworkPolicy(ctx context.Context) error {
	if !envTruthy(os.Getenv("RUNEWARD_K8S_NETWORK_POLICY")) {
		return nil
	}
	dnsPort := intstrTCPUDP()
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "runeward-default-deny",
			Labels: map[string]string{labelKey(labelManaged): "true"},
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Empty selector => applies to every pod in the namespace.
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// No Ingress rules => all ingress denied.
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			// Allow DNS resolution only; everything else is denied and must go
			// through runeward's egress proxy.
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				Ports: dnsPort,
			}},
		},
	}
	_, err := k.client.NetworkingV1().NetworkPolicies(k.namespace).Create(ctx, policy, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create default-deny network policy: %w", err)
	}
	return nil
}

// intstrTCPUDP returns the DNS (port 53) UDP+TCP port rules for the egress allow.
func intstrTCPUDP() []networkingv1.NetworkPolicyPort {
	udp := corev1.ProtocolUDP
	tcp := corev1.ProtocolTCP
	dns := intstr.FromInt(53)
	return []networkingv1.NetworkPolicyPort{
		{Protocol: &udp, Port: &dns},
		{Protocol: &tcp, Port: &dns},
	}
}

// envTruthy reports whether an env value should be treated as "on".
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (k *K8s) waitRunning(ctx context.Context, podName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pod, err := k.client.CoreV1().Pods(k.namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("wait for pod: %w", err)
		}
		if pod.Status.Phase == corev1.PodRunning {
			for _, cs := range pod.Status.ContainerStatuses {
				if cs.Name == k8sContainer && cs.Ready {
					return nil
				}
			}
		}
		if pod.Status.Phase == corev1.PodFailed {
			return fmt.Errorf("pod %s entered Failed phase", podName)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for pod %s to become ready (phase=%s)", podName, pod.Status.Phase)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

func (k *K8s) workdir(ctx context.Context, id string) (string, error) {
	pod, err := k.client.CoreV1().Pods(k.namespace).Get(ctx, containerName(id), metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	wd := pod.Spec.Containers[0].WorkingDir
	if wd == "" {
		wd = "/workspace"
	}
	return wd, nil
}

// stream executes a remotecommand against the sandbox container.
func (k *K8s) stream(ctx context.Context, podName string, opts corev1.PodExecOptions, stream remotecommand.StreamOptions) error {
	req := k.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(k.namespace).
		SubResource("exec").
		VersionedParams(&opts, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(k.rest, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("build executor: %w", err)
	}
	return exec.StreamWithContext(ctx, stream)
}

// wrapCommand injects an optional workdir and env into an argv command using a
// small sh wrapper (PodExecOptions has no working-dir/env fields).
func wrapCommand(workdir string, env map[string]string, cmd []string) []string {
	if workdir == "" && len(env) == 0 {
		return cmd
	}
	var b strings.Builder
	if workdir != "" {
		b.WriteString(`cd "$1" && shift; `)
	}
	for name, val := range env {
		// Skip names that aren't identifier-safe; interpolating them into the
		// `export` line would be a shell-injection vector.
		if validateEnvName(name) != nil {
			continue
		}
		fmt.Fprintf(&b, "export %s=%s; ", name, shellQuote(val))
	}
	b.WriteString(`exec "$@"`)

	out := []string{"sh", "-c", b.String(), "sh"}
	if workdir != "" {
		out = append(out, workdir)
	}
	return append(out, cmd...)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// termSizeQueue adapts the backend resize channel to remotecommand.
type termSizeQueue struct{ ch <-chan TermSize }

func (t *termSizeQueue) Next() *remotecommand.TerminalSize {
	s, ok := <-t.ch
	if !ok {
		return nil
	}
	return &remotecommand.TerminalSize{Width: s.Cols, Height: s.Rows}
}

func labelKey(k string) string { return k }

// egressConfigMapName names the per-sandbox ConfigMap holding the egress policy.
func egressConfigMapName(id string) string { return "runeward-egress-" + id }

func runtimeClassPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func boolPtr(b bool) *bool { return &b }

// appArmorProfile maps a profile's apparmor value to a k8s AppArmorProfile.
// "runtime/default" (or "runtime-default") selects the runtime default;
// "unconfined" disables it; any other value is a Localhost profile name.
func appArmorProfile(name string) *corev1.AppArmorProfile {
	switch name {
	case "runtime/default", "runtime-default":
		return &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}
	case "unconfined":
		return &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
	default:
		n := name
		return &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeLocalhost, LocalhostProfile: &n}
	}
}

func int64Ptr(i int64) *int64 { return &i }

// egressPullPolicy picks the pull policy for the egress sidecar/init image.
// The image is usually built locally and preloaded into the node, so don't
// force the registry pull Kubernetes defaults to for ":latest" tags.
// $RUNEWARD_EGRESS_PULL_POLICY (Always|Never|IfNotPresent) overrides.
func egressPullPolicy(_ string) corev1.PullPolicy {
	switch corev1.PullPolicy(os.Getenv("RUNEWARD_EGRESS_PULL_POLICY")) {
	case corev1.PullAlways:
		return corev1.PullAlways
	case corev1.PullNever:
		return corev1.PullNever
	default:
		return corev1.PullIfNotPresent
	}
}

// snapshotPath returns the tarball location, in the same cache dir the docker
// backend uses.
func snapshotPath(id string) string {
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	dir := cache + "/runeward/snapshots"
	_ = os.MkdirAll(dir, 0o755)
	return dir + "/" + id + ".tar"
}
