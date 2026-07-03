// Package backend abstracts the sandbox runtime so callers don't care whether
// a sandbox is a Docker container or a Kubernetes Pod.
package backend

import (
	"context"
	"io"
	"time"

	"github.com/adefemi171/runeward/internal/profile"
)

// Backend provisions and controls sandboxes for a given execution host.
type Backend interface {
	// Name identifies the backend implementation (e.g. "docker", "k8s").
	Name() string

	// Create provisions a new sandbox and returns its handle once it accepts exec calls.
	Create(ctx context.Context, spec Spec) (*Sandbox, error)

	// Exec runs a one-shot command in the sandbox and returns its result.
	Exec(ctx context.Context, id string, req ExecRequest) (*ExecResult, error)

	// AttachPTY attaches an interactive pseudo-terminal to the sandbox.
	AttachPTY(ctx context.Context, id string, io PTYStream) error

	// CopyFiles projects files into the running sandbox.
	CopyFiles(ctx context.Context, id string, files []profile.File) error

	// ExportWorkspace streams a tar of the workdir contents to w without modifying the sandbox.
	ExportWorkspace(ctx context.Context, id string, w io.Writer) error

	// Snapshot captures the sandbox workspace and returns a reference.
	Snapshot(ctx context.Context, id, name string) (*SnapshotRef, error)

	// Restore recreates a sandbox seeded from a snapshot reference.
	Restore(ctx context.Context, ref SnapshotRef) (*Sandbox, error)

	// Kill terminates and removes the sandbox and its ephemeral resources.
	Kill(ctx context.Context, id string) error

	// List returns all sandboxes managed by this backend.
	List(ctx context.Context) ([]Sandbox, error)
}

// Spec is the resolved, backend-agnostic description of a sandbox to create.
type Spec struct {
	Profile string
	Image   string
	Workdir string
	User    string
	// Env values are already-resolved literals; secret resolution happens earlier.
	Env    map[string]string
	Labels map[string]string
	Files  []profile.File
	// SeedDir is a local directory copied into the workspace at creation
	// (a copy, never a mount; the source is only read).
	SeedDir   string
	Network   profile.Network
	Resources Resources
	// RuntimeClass maps to k8s runtimeClassName; ignored by the docker backend.
	RuntimeClass string
}

// Resources are best-effort resource caps applied to the sandbox.
type Resources struct {
	// NanoCPUs is in units of 1e-9 CPUs (1.5 CPUs = 1_500_000_000).
	NanoCPUs    int64
	MemoryBytes int64
}

// Sandbox is a handle to a provisioned sandbox.
type Sandbox struct {
	ID        string
	Profile   string
	Backend   string
	Image     string
	Status    string
	CreatedAt time.Time
	Endpoint  string
}

// ExecRequest is a one-shot command execution.
type ExecRequest struct {
	Command []string
	Workdir string
	Env     map[string]string
	Timeout time.Duration
}

// ExecResult captures the outcome of an Exec.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}

// PTYStream carries the interactive terminal I/O for AttachPTY.
type PTYStream struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	TTY    bool
	// Command defaults to an interactive shell when empty.
	Command []string
	// Resize delivers terminal size changes; may be nil.
	Resize <-chan TermSize
}

// TermSize is a terminal window dimension update.
type TermSize struct {
	Rows uint16
	Cols uint16
}

// SnapshotRef identifies a captured workspace snapshot.
type SnapshotRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Backend string `json:"backend"`
	// Location is backend-specific (e.g. a tarball path).
	Location string    `json:"location"`
	Created  time.Time `json:"created"`
}
