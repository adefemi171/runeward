package backend

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Runewardd/runeward/internal/profile"
)

const containerRuntimeEnv = "RUNEWARD_CONTAINER_RUNTIME"

var (
	containerRuntimeLookPath = exec.LookPath
	newDockerBackend         = func() (Backend, error) { return NewDocker() }
	newPodmanBackend         = func() (Backend, error) { return NewPodman() }
)

// For returns the backend implementing the profile's execution host.
func For(p *profile.Profile) (Backend, error) {
	switch p.Host.Type {
	case profile.HostContainer, "":
		runtime, err := selectContainerRuntime()
		if err != nil {
			return nil, err
		}
		if runtime == "podman" {
			return newPodmanBackend()
		}
		return newDockerBackend()
	case profile.HostK8s:
		return NewK8s()
	default:
		return nil, fmt.Errorf("no backend for host.type %q", p.Host.Type)
	}
}

func selectContainerRuntime() (string, error) {
	runtime := strings.ToLower(strings.TrimSpace(os.Getenv(containerRuntimeEnv)))
	switch runtime {
	case "":
		if _, err := containerRuntimeLookPath("docker"); err != nil {
			if _, podmanErr := containerRuntimeLookPath("podman"); podmanErr == nil {
				return "podman", nil
			}
		}
		return "docker", nil
	case "docker", "podman":
		return runtime, nil
	default:
		return "", fmt.Errorf("unsupported %s %q (want docker or podman)", containerRuntimeEnv, runtime)
	}
}

// SpecFromProfile derives a backend-agnostic Spec from a resolved profile.
// Env values are expected to already be resolved to literals by the caller.
func SpecFromProfile(p *profile.Profile, env map[string]string) Spec {
	return Spec{
		Profile:      p.Name,
		Image:        p.Host.Image,
		Workdir:      p.Host.Workdir,
		User:         p.Host.User,
		Env:          env,
		Files:        p.Files,
		SeedDir:      expandHome(p.Host.CopyFrom),
		Network:      p.Network,
		RuntimeClass: p.Host.RuntimeClass,
		ReadOnly:     p.Host.ReadOnly,
		Seccomp:      p.Host.Seccomp,
		AppArmor:     p.Host.AppArmor,
		Resources:    resourcesFromLimits(p.Limits),
		Labels: map[string]string{
			labelProfile: p.Name,
		},
	}
}

type restoreWithSpecBackend interface {
	RestoreWithSpec(ctx context.Context, ref SnapshotRef, spec Spec) (*Sandbox, error)
}

// RestoreSnapshot restores a snapshot using the full spec path when supported.
func RestoreSnapshot(ctx context.Context, be Backend, ref SnapshotRef, spec Spec) (*Sandbox, error) {
	if rb, ok := be.(restoreWithSpecBackend); ok {
		return rb.RestoreWithSpec(ctx, ref, spec)
	}
	return be.Restore(ctx, ref)
}

// resourcesFromLimits maps a profile's declared CPU/memory limits onto backend
// resource caps. Previously these limits were parsed but never applied.
func resourcesFromLimits(l profile.Limits) Resources {
	var r Resources
	if l.Memory != "" {
		if b, ok := parseSize(l.Memory); ok {
			r.MemoryBytes = b
		}
	}
	if l.CPUs > 0 {
		r.NanoCPUs = int64(l.CPUs * 1e9)
	}
	return r
}
