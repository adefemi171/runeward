package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Runewardd/runeward/internal/egress"
	"github.com/Runewardd/runeward/internal/profile"
	"github.com/creack/pty"
)

// Docker provisions one container per sandbox. It drives the docker CLI
// rather than the SDK; the CLI contract is more stable across
type Docker struct {
	runtime string
	bin     string
	snapDir string

	proxyMu sync.Mutex
	proxies map[string]*hostProxy
	// egressCtr maps a sandbox id to its transparent-egress sidecar container
	// name (strict mode only), so it can be torn down with the sandbox.
	egressCtr map[string]string
}

const (
	labelManaged = "runeward.managed"
	labelProfile = "runeward.profile"
	labelID      = "runeward.id"
	labelVolume  = "runeward.volume"
)

// NewDocker returns a Docker backend, verifying the CLI is present and the
// engine is actually reachable so misconfig fails fast with a clear message.
func NewDocker() (*Docker, error) {
	return newDockerWithRuntime("docker")
}

func newDockerWithRuntime(runtime string) (*Docker, error) {
	bin, err := exec.LookPath(runtime)
	if err != nil {
		return nil, fmt.Errorf("%s CLI not found in PATH (install %s and add it to your PATH): %w", runtime, runtime, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, bin, "version", "--format", "{{.Server.Version}}")
	var perr bytes.Buffer
	probe.Stderr = &perr
	if err := probe.Run(); err != nil {
		detail := strings.TrimSpace(perr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("%s engine not reachable; is %s running? (%s)", runtime, runtime, detail)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	snapDir := filepath.Join(cache, "runeward", "snapshots")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return nil, fmt.Errorf("create snapshot dir: %w", err)
	}
	return &Docker{
		runtime:   runtime,
		bin:       bin,
		snapDir:   snapDir,
		proxies:   make(map[string]*hostProxy),
		egressCtr: make(map[string]string),
	}, nil
}

func (d *Docker) Name() string {
	if d.runtime == "" {
		return "docker"
	}
	return d.runtime
}

func (d *Docker) Create(ctx context.Context, spec Spec) (*Sandbox, error) {
	id := newID()
	name := containerName(id)
	vol := volumeName(id)

	if err := d.run(ctx, "volume", "create", "--label", kv(labelManaged, "true"),
		"--label", kv(labelID, id), vol); err != nil {
		return nil, fmt.Errorf("create workspace volume: %w", err)
	}

	workdir := spec.Workdir
	if workdir == "" {
		workdir = "/workspace"
	}

	var hp *hostProxy
	var egressEnv map[string]string
	var egressCtrName string // transparent-egress sidecar (strict mode)
	if spec.Network.DenyByDefault() {
		if spec.Network.StrictEgress() {
			// Transparent L3 enforcement: a sidecar container owns the network
			// namespace, installs iptables REDIRECT rules, and runs the
			// transparent proxy; the sandbox joins that netns so *all* TCP is
			// forced through the proxy regardless of proxy env vars. This can't
			// be bypassed by code that ignores HTTP(S)_PROXY.
			ctrName, err := d.startEgressContainer(ctx, id, spec.Network)
			if err != nil {
				_ = d.run(context.Background(), "volume", "rm", "-f", vol)
				return nil, err
			}
			egressCtrName = ctrName
		} else {
			// Cooperative mode enforces hostname policy through HTTP(S)_PROXY, but
			// cannot fully police non-proxy protocols (like UDP/QUIC) without the
			// strict sidecar/netns path.
			p, err := startHostProxy(policyFromNetwork(spec.Network), log.New(os.Stderr, "runeward-egress "+id+" ", log.LstdFlags))
			if err != nil {
				_ = d.run(context.Background(), "volume", "rm", "-f", vol)
				return nil, fmt.Errorf("start egress proxy: %w", err)
			}
			hp = p
			egressEnv = proxyEnv(fmt.Sprintf("http://%s:%s@%s:%d", p.user, p.pass, d.hostGatewayName(), p.port))
		}
	}

	args := []string{"run", "-d",
		"--name", name,
		"--label", kv(labelManaged, "true"),
		"--label", kv(labelProfile, spec.Profile),
		"--label", kv(labelID, id),
		"--label", kv(labelVolume, vol),
		"-w", workdir,
		"-v", vol + ":" + workdir,
	}
	if egressCtrName != "" {
		// Share the sidecar's network namespace; enforcement is transparent at
		// L3, so no HTTP(S)_PROXY env and no host-gateway mapping.
		args = append(args, "--network", "container:"+egressCtrName)
	}
	if hp != nil {
		if d.Name() == "docker" {
			args = append(args, "--add-host", "host.docker.internal:host-gateway")
		}
		// Prevent IPv6 egress bypass in cooperative mode where only HTTP(S)
		// traffic is proxied.
		args = append(args,
			"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
			"--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
		)
	}
	if spec.RuntimeClass != "" {
		args = append(args, "--runtime", spec.RuntimeClass)
	}

	args = append(args,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	)
	// Docker applies its default seccomp profile unless overridden; allow a
	// profile to point at a stricter one, and optionally pin AppArmor.
	if spec.Seccomp != "" {
		args = append(args, "--security-opt", "seccomp="+spec.Seccomp)
	}
	if spec.AppArmor != "" {
		args = append(args, "--security-opt", "apparmor="+spec.AppArmor)
	}
	if spec.ReadOnly {
		// Read-only root with a writable tmpfs for /tmp; the workspace volume
		// stays writable via its own mount.
		args = append(args, "--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,size=512m")
	}
	if pids := defaultPidsLimit(); pids > 0 {
		args = append(args, "--pids-limit", strconv.FormatInt(pids, 10))
	}
	if spec.User != "" {
		args = append(args, "-u", spec.User)
	}
	for k, v := range spec.Env {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range egressEnv {
		args = append(args, "-e", k+"="+v)
	}
	for k, v := range spec.Labels {
		args = append(args, "--label", kv(k, v))
	}

	mem := spec.Resources.MemoryBytes
	if mem == 0 {
		mem = defaultMemoryBytes()
	}
	if mem > 0 {
		args = append(args, "--memory", fmt.Sprintf("%d", mem))
	}
	nanoCPUs := spec.Resources.NanoCPUs
	if nanoCPUs == 0 {
		nanoCPUs = defaultNanoCPUs()
	}
	if nanoCPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.3f", float64(nanoCPUs)/1e9))
	}
	image := spec.Image
	if image == "" {
		image = "debian:stable-slim"
	}

	args = append(args, image, "sleep", "infinity")

	if err := d.run(ctx, args...); err != nil {
		hp.stop()
		if egressCtrName != "" {
			_ = d.run(context.Background(), "rm", "-f", egressCtrName)
		}
		_ = d.run(context.Background(), "volume", "rm", "-f", vol)
		if spec.RuntimeClass != "" {
			return nil, fmt.Errorf("run container with runtime %q: is it registered with the docker engine? (see docs/security-model.md): %w", spec.RuntimeClass, err)
		}
		return nil, fmt.Errorf("run container: %w", err)
	}

	if hp != nil {
		d.proxyMu.Lock()
		d.proxies[id] = hp
		d.proxyMu.Unlock()
	}
	if egressCtrName != "" {
		d.proxyMu.Lock()
		d.egressCtr[id] = egressCtrName
		d.proxyMu.Unlock()
	}

	if spec.SeedDir != "" {
		if err := d.seedWorkspace(ctx, id, workdir, spec.SeedDir); err != nil {
			_ = d.Kill(context.Background(), id)
			return nil, err
		}
	}

	if len(spec.Files) > 0 {
		if err := d.CopyFiles(ctx, id, spec.Files); err != nil {
			_ = d.Kill(context.Background(), id)
			return nil, err
		}
	}

	return &Sandbox{
		ID:        id,
		Profile:   spec.Profile,
		Backend:   d.Name(),
		Image:     image,
		Status:    "running",
		CreatedAt: time.Now(),
	}, nil
}

func (d *Docker) Exec(ctx context.Context, id string, req ExecRequest) (*ExecResult, error) {
	args := []string{"exec"}
	if req.Workdir != "" {
		args = append(args, "-w", req.Workdir)
	}
	for k, v := range req.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, containerName(id))
	args = append(args, req.Command...)

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, d.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	res := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("%s exec: %w", d.Name(), err)
	}
	return res, nil
}

func (d *Docker) AttachPTY(ctx context.Context, id string, s PTYStream) error {
	command := s.Command
	if len(command) == 0 {
		command = []string{"/bin/sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"}
	}
	args := []string{"exec", "-i"}
	if s.TTY {
		args = append(args, "-t")
	}
	args = append(args, containerName(id))
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, d.bin, args...)

	if !s.TTY {
		cmd.Stdin = s.Stdin
		cmd.Stdout = s.Stdout
		if s.Stderr != nil {
			cmd.Stderr = s.Stderr
		} else {
			cmd.Stderr = s.Stdout
		}
		return cmd.Run()
	}

	f, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}
	defer func() { _ = f.Close() }()

	if s.Resize != nil {
		go func() {
			for size := range s.Resize {
				_ = pty.Setsize(f, &pty.Winsize{Rows: size.Rows, Cols: size.Cols})
			}
		}()
	}

	if s.Stdin != nil {
		go func() {
			_, _ = io.Copy(f, s.Stdin)
			_ = f.Close()
		}()
	}
	if s.Stdout != nil {
		_, _ = io.Copy(s.Stdout, f)
	}
	return cmd.Wait()
}

func (d *Docker) CopyFiles(ctx context.Context, id string, files []profile.File) error {
	for _, f := range files {
		if err := validateProjectionPath(f.Path); err != nil {
			return err
		}
		if err := validateFileMode(f.Mode); err != nil {
			return err
		}
		var data []byte
		if f.Content != "" {
			data = []byte(f.Content)
		} else if f.File != "" {
			b, err := os.ReadFile(expandHome(f.File))
			if err != nil {
				return fmt.Errorf("read projected file %q: %w", f.File, err)
			}
			data = b
		} else {
			continue
		}

		tmp, err := os.CreateTemp("", "runeward-proj-*")
		if err != nil {
			return err
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
		tmp.Close()

		dir := filepath.Dir(f.Path)
		if dir != "" && dir != "." && dir != "/" {
			_ = d.run(ctx, "exec", containerName(id), "mkdir", "-p", dir)
		}
		if err := d.run(ctx, "cp", tmp.Name(), containerName(id)+":"+f.Path); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("copy file into sandbox: %w", err)
		}
		os.Remove(tmp.Name())

		mode := f.Mode
		if mode == "" {
			mode = "0444"
		}
		_ = d.run(ctx, "exec", containerName(id), "chmod", mode, f.Path)
		_ = d.run(ctx, "exec", containerName(id), "chown", "root:root", f.Path)
	}
	return nil
}

// seedWorkspace streams srcDir as a tar and extracts it inside the container.
func (d *Docker) seedWorkspace(ctx context.Context, id, workdir, srcDir string) error {
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

	cmd := exec.CommandContext(ctx, d.bin, "exec", "-i", containerName(id), "tar", "-C", workdir, "-xf", "-")
	cmd.Stdin = pr
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("seed workspace from %q: %w: %s", srcDir, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ExportWorkspace streams a tar of the container workdir contents to w.
func (d *Docker) ExportWorkspace(ctx context.Context, id string, w io.Writer) error {
	workdir, err := d.workdir(ctx, id)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, d.bin, "exec", containerName(id), "tar", "-C", workdir, "-cf", "-", ".")
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("export workspace: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// has reports whether a container for id exists on this Docker host.
func (d *Docker) has(ctx context.Context, id string) bool {
	_, err := d.output(ctx, "inspect", "-f", "{{.Id}}", containerName(id))
	return err == nil
}

func (d *Docker) Snapshot(ctx context.Context, id, name string) (*SnapshotRef, error) {
	workdir, err := d.workdir(ctx, id)
	if err != nil {
		return nil, err
	}
	snapID := newID()
	loc := filepath.Join(d.snapDir, snapID+".tar")
	out, err := os.Create(loc)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	cmd := exec.CommandContext(ctx, d.bin, "exec", containerName(id), "tar", "-C", workdir, "-cf", "-", ".")
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		os.Remove(loc)
		return nil, fmt.Errorf("snapshot tar: %w: %s", err, stderr.String())
	}
	_ = out.Close()
	sum, err := hashFile(loc)
	if err != nil {
		os.Remove(loc)
		return nil, fmt.Errorf("snapshot hash: %w", err)
	}
	return &SnapshotRef{
		ID:       snapID,
		Name:     name,
		Backend:  d.Name(),
		Location: loc,
		Sha256:   sum,
		Created:  time.Now(),
	}, nil
}

func (d *Docker) Restore(ctx context.Context, ref SnapshotRef) (*Sandbox, error) {
	return d.RestoreWithSpec(ctx, ref, Spec{Profile: ref.Profile})
}

func (d *Docker) RestoreWithSpec(ctx context.Context, ref SnapshotRef, spec Spec) (*Sandbox, error) {
	if spec.Profile == "" {
		spec.Profile = ref.Profile
	}
	sb, err := d.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	workdir, err := d.workdir(ctx, sb.ID)
	if err != nil {
		_ = d.Kill(context.Background(), sb.ID)
		return nil, err
	}
	if err := verifySnapshot(ref); err != nil {
		_ = d.Kill(context.Background(), sb.ID)
		return nil, err
	}
	in, err := os.Open(ref.Location)
	if err != nil {
		_ = d.Kill(context.Background(), sb.ID)
		return nil, err
	}
	defer in.Close()

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(filterTarSafe(pw, in)) }()

	cmd := exec.CommandContext(ctx, d.bin, "exec", "-i", containerName(sb.ID), "tar", "-C", workdir, "-xf", "-")
	cmd.Stdin = pr
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = d.Kill(context.Background(), sb.ID)
		return nil, fmt.Errorf("restore untar: %w: %s", err, stderr.String())
	}
	return sb, nil
}

func (d *Docker) Kill(ctx context.Context, id string) error {
	d.proxyMu.Lock()
	hp := d.proxies[id]
	delete(d.proxies, id)
	egressCtrName := d.egressCtr[id]
	delete(d.egressCtr, id)
	d.proxyMu.Unlock()
	hp.stop()

	vol, _ := d.volumeOf(ctx, id)
	if err := d.run(ctx, "rm", "-f", containerName(id)); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	// Tear down the transparent-egress sidecar after the sandbox that shared
	// its netns is gone.
	if egressCtrName != "" {
		_ = d.run(ctx, "rm", "-f", egressCtrName)
	}
	if vol != "" {
		_ = d.run(ctx, "volume", "rm", "-f", vol)
	}
	return nil
}

// egressContainerName is the sidecar name for a sandbox's transparent egress.
func egressContainerName(id string) string { return "runeward-egress-" + id }

// startEgressContainer launches the transparent-egress sidecar for strict-mode
// Docker sandboxes. The container installs iptables REDIRECT rules (NET_ADMIN),
// drops to the exempt uid, and serves the transparent proxy; the sandbox then
// joins its network namespace. Returns the sidecar container name.
func (d *Docker) startEgressContainer(ctx context.Context, id string, net profile.Network) (string, error) {
	img := os.Getenv("RUNEWARD_EGRESS_IMAGE")
	if img == "" {
		img = "runeward-egress:latest"
	}
	name := egressContainerName(id)

	polJSON, err := json.Marshal(policyFromNetwork(net))
	if err != nil {
		return "", fmt.Errorf("marshal egress policy: %w", err)
	}

	args := []string{"run", "-d",
		"--name", name,
		"--label", kv(labelManaged, "true"),
		"--label", kv(labelID, id),
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW",
		"-e", "RUNEWARD_EGRESS_POLICY=" + string(polJSON),
	}
	// Propagate optional DNS-resolver pinning into the sidecar's netns.
	if r := strings.TrimSpace(os.Getenv("RUNEWARD_DNS_RESOLVERS")); r != "" {
		args = append(args, "-e", "RUNEWARD_DNS_RESOLVERS="+r)
	}
	args = append(args, img,
		"--setup-iptables", "--transparent",
		"--redirect-port", strconv.Itoa(egress.StrictRedirectPort),
		"--proxy-uid", strconv.Itoa(egress.StrictProxyUID),
	)

	if err := d.run(ctx, args...); err != nil {
		return "", fmt.Errorf("start transparent egress sidecar: %w", err)
	}
	if err := d.waitEgressReady(ctx, name); err != nil {
		_ = d.run(context.Background(), "rm", "-f", name)
		return "", err
	}
	return name, nil
}

// waitEgressReady blocks until the sidecar's transparent proxy is listening
// (which happens only after the iptables rules are installed), or errors if the
// container exits first. This closes the window where a sandbox could egress
// before enforcement is in place.
func (d *Docker) waitEgressReady(ctx context.Context, name string) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := d.output(ctx, "logs", name)
		if strings.Contains(logs, "transparent proxy listening") {
			return nil
		}
		if st, err := d.output(ctx, "inspect", "-f", "{{.State.Running}}", name); err == nil {
			if strings.TrimSpace(st) == "false" {
				return fmt.Errorf("egress sidecar exited before it was ready: %s", strings.TrimSpace(logs))
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for transparent egress proxy to become ready")
}

func (d *Docker) List(ctx context.Context) ([]Sandbox, error) {
	out, err := d.output(ctx, "ps", "-a",
		"--filter", "label="+labelManaged+"=true",
		"--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	var sandboxes []Sandbox
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var row struct {
			Labels    string `json:"Labels"`
			Image     string `json:"Image"`
			State     string `json:"State"`
			CreatedAt string `json:"CreatedAt"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		labels := parseLabels(row.Labels)
		sandboxes = append(sandboxes, Sandbox{
			ID:      labels[labelID],
			Profile: labels[labelProfile],
			Backend: d.Name(),
			Image:   row.Image,
			Status:  row.State,
		})
	}
	return sandboxes, nil
}

func (d *Docker) run(ctx context.Context, args ...string) error {
	_, err := d.output(ctx, args...)
	return err
}

func (d *Docker) output(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, d.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", d.Name(), args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (d *Docker) hostGatewayName() string {
	if d.Name() == "podman" {
		return "host.containers.internal"
	}
	return "host.docker.internal"
}

func (d *Docker) workdir(ctx context.Context, id string) (string, error) {
	out, err := d.output(ctx, "inspect", "-f", "{{.Config.WorkingDir}}", containerName(id))
	if err != nil {
		return "", err
	}
	wd := strings.TrimSpace(out)
	if wd == "" {
		wd = "/workspace"
	}
	return wd, nil
}

func (d *Docker) volumeOf(ctx context.Context, id string) (string, error) {
	out, err := d.output(ctx, "inspect", "-f",
		fmt.Sprintf("{{index .Config.Labels %q}}", labelVolume), containerName(id))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Secure-by-default resource ceilings for a cell. Each is overridable via an
// environment variable; setting the variable to "0" or "off" disables that cap.
const (
	fallbackMemoryBytes int64 = 4 << 30 // 4 GiB
	fallbackNanoCPUs    int64 = 2e9     // 2.0 CPUs
	fallbackPidsLimit   int64 = 1024
)

// defaultMemoryBytes returns the default memory cap in bytes, honoring
// RUNEWARD_SANDBOX_MEMORY (accepts a byte count or a k/m/g suffix; "0"/"off"
// disables the cap).
func defaultMemoryBytes() int64 {
	return limitFromEnv("RUNEWARD_SANDBOX_MEMORY", fallbackMemoryBytes, parseSize)
}

// defaultNanoCPUs returns the default CPU cap in nano-CPUs, honoring
// RUNEWARD_SANDBOX_CPUS (a float like "1.5"; "0"/"off" disables the cap).
func defaultNanoCPUs() int64 {
	return limitFromEnv("RUNEWARD_SANDBOX_CPUS", fallbackNanoCPUs, func(s string) (int64, bool) {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || f < 0 {
			return 0, false
		}
		return int64(f * 1e9), true
	})
}

// defaultPidsLimit returns the default max process count, honoring
// RUNEWARD_SANDBOX_PIDS ("0"/"off" disables the cap).
func defaultPidsLimit() int64 {
	return limitFromEnv("RUNEWARD_SANDBOX_PIDS", fallbackPidsLimit, func(s string) (int64, bool) {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	})
}

// limitFromEnv resolves a resource limit: the fallback when unset, 0 (disabled)
// for "0"/"off"/"none", or the parsed value; an unparseable value keeps the
// fallback.
func limitFromEnv(key string, fallback int64, parse func(string) (int64, bool)) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	switch strings.ToLower(v) {
	case "":
		return fallback
	case "0", "off", "none":
		return 0
	}
	if n, ok := parse(v); ok {
		return n
	}
	return fallback
}

// parseSize parses a byte size that may carry a k/m/g/t suffix (base-2, case
// insensitive; a bare number is bytes).
func parseSize(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	switch last := s[len(s)-1]; last {
	case 'k', 'K':
		mult, s = 1<<10, s[:len(s)-1]
	case 'm', 'M':
		mult, s = 1<<20, s[:len(s)-1]
	case 'g', 'G':
		mult, s = 1<<30, s[:len(s)-1]
	case 't', 'T':
		mult, s = 1<<40, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n * mult, true
}

func containerName(id string) string { return "runeward-" + id }
func volumeName(id string) string    { return "runeward-vol-" + id }
func kv(k, v string) string          { return k + "=" + v }

func newID() string {
	b := make([]byte, 16) // 128-bit: unguessable even without auth
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func parseLabels(s string) map[string]string {
	m := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(pair, "="); ok {
			m[k] = v
		}
	}
	return m
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
