package backend

// NewPodman returns a Podman-backed container backend.
func NewPodman() (*Docker, error) {
	return newDockerWithRuntime("podman")
}
