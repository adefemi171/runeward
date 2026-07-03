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
	"strings"
	"sync"
	"time"

	"github.com/adefemi171/runeward/internal/profile"
	"github.com/creack/pty"
)

// Docker provisions one container per sandbox. It drives the docker CLI
// rather than the SDK; the CLI contract is more stable across
// Docker/OrbStack/Podman.
type Docker struct {
	bin     string
	snapDir string

	proxyMu sync.Mutex
	proxies map[string]*hostProxy
}

const (
	labelManaged = "runeward.managed"
	labelProfile = "runeward.profile"
	labelID      = "runeward.id"
	labelVolume  = "runeward.volume"
)

// NewDocker returns a Docker backend, verifying the CLI is reachable.
func NewDocker() (*Docker, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("docker CLI not found in PATH: %w", err)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	snapDir := filepath.Join(cache, "runeward", "snapshots")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return nil, fmt.Errorf("create snapshot dir: %w", err)
	}
	return &Docker{bin: bin, snapDir: snapDir, proxies: make(map[string]*hostProxy)}, nil
}

func (d *Docker) Name() string { return "docker" }

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

	// Deny-by-default profiles get an egress proxy on the host, reached via HTTP(S)_PROXY.
	var hp *hostProxy
	var egressEnv map[string]string
	if spec.Network.DenyByDefault() {
		p, err := startHostProxy(policyFromNetwork(spec.Network), log.New(os.Stderr, "runeward-egress "+id+" ", log.LstdFlags))
		if err != nil {
			_ = d.run(context.Background(), "volume", "rm", "-f", vol)
			return nil, fmt.Errorf("start egress proxy: %w", err)
		}
		hp = p
		egressEnv = proxyEnv(fmt.Sprintf("http://host.docker.internal:%d", p.port))
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
	if hp != nil {
		// host.docker.internal doesn't resolve on Linux without this.
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
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
	if spec.Resources.MemoryBytes > 0 {
		args = append(args, "--memory", fmt.Sprintf("%d", spec.Resources.MemoryBytes))
	}
	if spec.Resources.NanoCPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.3f", float64(spec.Resources.NanoCPUs)/1e9))
	}
	image := spec.Image
	if image == "" {
		image = "debian:stable-slim"
	}
	// Keep the container alive so we can exec into it repeatedly.
	args = append(args, image, "sleep", "infinity")

	if err := d.run(ctx, args...); err != nil {
		hp.stop()
		_ = d.run(context.Background(), "volume", "rm", "-f", vol)
		return nil, fmt.Errorf("run container: %w", err)
	}

	if hp != nil {
		d.proxyMu.Lock()
		d.proxies[id] = hp
		d.proxyMu.Unlock()
	}

	// Seed before projecting [[file]] entries so those can sit on top.
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
		return res, fmt.Errorf("docker exec: %w", err)
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

	// Non-TTY: use plain pipes so stdin EOF propagates; a PTY slave never
	// sees EOF and the inner shell would hang.
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
			// Close so the remote shell sees EOF and exits.
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
// Extraction runs as the container's default user so files end up owned by
// the sandbox user; the host directory is only read.
func (d *Docker) seedWorkspace(ctx context.Context, id, workdir, srcDir string) error {
	if fi, err := os.Stat(srcDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("copy_from %q must be an existing directory: %v", srcDir, err)
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeDirTar(pw, srcDir)) }()

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
	return &SnapshotRef{
		ID:       snapID,
		Name:     name,
		Backend:  d.Name(),
		Location: loc,
		Created:  time.Now(),
	}, nil
}

func (d *Docker) Restore(ctx context.Context, ref SnapshotRef) (*Sandbox, error) {
	sb, err := d.Create(ctx, Spec{Profile: ref.Profile})
	if err != nil {
		return nil, err
	}
	workdir, err := d.workdir(ctx, sb.ID)
	if err != nil {
		_ = d.Kill(context.Background(), sb.ID)
		return nil, err
	}
	in, err := os.Open(ref.Location)
	if err != nil {
		_ = d.Kill(context.Background(), sb.ID)
		return nil, err
	}
	defer in.Close()

	cmd := exec.CommandContext(ctx, d.bin, "exec", "-i", containerName(sb.ID), "tar", "-C", workdir, "-xf", "-")
	cmd.Stdin = in
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
	d.proxyMu.Unlock()
	hp.stop()

	vol, _ := d.volumeOf(ctx, id)
	if err := d.run(ctx, "rm", "-f", containerName(id)); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	if vol != "" {
		_ = d.run(ctx, "volume", "rm", "-f", vol)
	}
	return nil
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

// --- helpers ---

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
		return stdout.String(), fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
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

func containerName(id string) string { return "runeward-" + id }
func volumeName(id string) string    { return "runeward-vol-" + id }
func kv(k, v string) string          { return k + "=" + v }

func newID() string {
	b := make([]byte, 6)
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
