package backend

import (
	"errors"
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
)

func TestSelectContainerRuntime(t *testing.T) {
	origLookPath := containerRuntimeLookPath
	t.Cleanup(func() { containerRuntimeLookPath = origLookPath })

	t.Run("defaults to docker when available", func(t *testing.T) {
		t.Setenv(containerRuntimeEnv, "")
		containerRuntimeLookPath = func(file string) (string, error) {
			if file == "docker" {
				return "/usr/bin/docker", nil
			}
			return "", errors.New("not found")
		}

		got, err := selectContainerRuntime()
		if err != nil {
			t.Fatalf("selectContainerRuntime() error = %v", err)
		}
		if got != "docker" {
			t.Fatalf("selectContainerRuntime() = %q, want docker", got)
		}
	})

	t.Run("auto-detects podman when docker is absent", func(t *testing.T) {
		t.Setenv(containerRuntimeEnv, "")
		containerRuntimeLookPath = func(file string) (string, error) {
			if file == "podman" {
				return "/usr/bin/podman", nil
			}
			return "", errors.New("not found")
		}

		got, err := selectContainerRuntime()
		if err != nil {
			t.Fatalf("selectContainerRuntime() error = %v", err)
		}
		if got != "podman" {
			t.Fatalf("selectContainerRuntime() = %q, want podman", got)
		}
	})

	t.Run("honors env override", func(t *testing.T) {
		t.Setenv(containerRuntimeEnv, "podman")
		got, err := selectContainerRuntime()
		if err != nil {
			t.Fatalf("selectContainerRuntime() error = %v", err)
		}
		if got != "podman" {
			t.Fatalf("selectContainerRuntime() = %q, want podman", got)
		}
	})

	t.Run("rejects invalid env override", func(t *testing.T) {
		t.Setenv(containerRuntimeEnv, "containerd")
		if _, err := selectContainerRuntime(); err == nil {
			t.Fatalf("selectContainerRuntime() error = nil, want non-nil")
		}
	})
}

func TestForContainerRuntimeSelection(t *testing.T) {
	origLookPath := containerRuntimeLookPath
	origDockerCtor := newDockerBackend
	origPodmanCtor := newPodmanBackend
	t.Cleanup(func() {
		containerRuntimeLookPath = origLookPath
		newDockerBackend = origDockerCtor
		newPodmanBackend = origPodmanCtor
	})

	t.Run("uses podman when env requests it", func(t *testing.T) {
		t.Setenv(containerRuntimeEnv, "podman")
		dockerCalls := 0
		podmanCalls := 0
		newDockerBackend = func() (Backend, error) {
			dockerCalls++
			return &Docker{runtime: "docker"}, nil
		}
		newPodmanBackend = func() (Backend, error) {
			podmanCalls++
			return &Docker{runtime: "podman"}, nil
		}

		be, err := For(&profile.Profile{})
		if err != nil {
			t.Fatalf("For() error = %v", err)
		}
		if be.Name() != "podman" {
			t.Fatalf("For() backend = %q, want podman", be.Name())
		}
		if dockerCalls != 0 || podmanCalls != 1 {
			t.Fatalf("constructor calls docker=%d podman=%d, want docker=0 podman=1", dockerCalls, podmanCalls)
		}
	})

	t.Run("uses docker by default", func(t *testing.T) {
		t.Setenv(containerRuntimeEnv, "")
		containerRuntimeLookPath = func(file string) (string, error) {
			if file == "docker" {
				return "/usr/bin/docker", nil
			}
			return "", errors.New("not found")
		}
		dockerCalls := 0
		podmanCalls := 0
		newDockerBackend = func() (Backend, error) {
			dockerCalls++
			return &Docker{runtime: "docker"}, nil
		}
		newPodmanBackend = func() (Backend, error) {
			podmanCalls++
			return &Docker{runtime: "podman"}, nil
		}

		be, err := For(&profile.Profile{})
		if err != nil {
			t.Fatalf("For() error = %v", err)
		}
		if be.Name() != "docker" {
			t.Fatalf("For() backend = %q, want docker", be.Name())
		}
		if dockerCalls != 1 || podmanCalls != 0 {
			t.Fatalf("constructor calls docker=%d podman=%d, want docker=1 podman=0", dockerCalls, podmanCalls)
		}
	})
}
