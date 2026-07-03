package profile

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"sigs.k8s.io/yaml"
)

// ErrNotFound is returned when a profile name cannot be resolved.
var ErrNotFound = errors.New("profile not found")

// profileExts is in resolution order: within a directory the earliest
// extension wins, so foo.toml shadows foo.yaml.
var profileExts = []string{".toml", ".yaml", ".yml", ".json"}

// Options controls where profiles are resolved from.
type Options struct {
	// ConfigDir, when set, pins the search to a single directory.
	ConfigDir string
	// WorkingDir resolves project-local profiles; defaults to the process cwd.
	WorkingDir string
}

// Load resolves and parses the named profile; the file extension selects the
// parser.
//
// Resolution order (first match wins):
//  1. <workingdir>/.runeward/<name>.{toml,yaml,yml,json}
//  2. $XDG_CONFIG_HOME/runeward/... or ~/.config/runeward/...
//
// Within a directory, extensions are tried in profileExts order, so
// <name>.toml shadows <name>.yaml. If Options.ConfigDir is set, only that
// directory is consulted.
func Load(name string, opts Options) (*Profile, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	for _, dir := range searchDirs(opts) {
		for _, ext := range profileExts {
			path := filepath.Join(dir, name+ext)
			if _, err := os.Stat(path); err == nil {
				return parseFile(path, name)
			}
		}
	}
	return nil, fmt.Errorf("%w: %q (searched %s)", ErrNotFound, name, strings.Join(searchDirs(opts), ", "))
}

// List returns the names of all profiles on the search path, de-duplicated
// with earlier tiers shadowing later ones.
func List(opts Options) ([]string, error) {
	seen := map[string]struct{}{}
	var names []string
	for _, dir := range searchDirs(opts) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // missing tier is not an error
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := filepath.Ext(e.Name())
			if !isProfileExt(ext) {
				continue
			}
			n := strings.TrimSuffix(e.Name(), ext)
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// searchDirs returns the ordered list of directories to consult.
func searchDirs(opts Options) []string {
	if opts.ConfigDir != "" {
		return []string{opts.ConfigDir}
	}
	wd := opts.WorkingDir
	if wd == "" {
		wd, _ = os.Getwd()
	}
	dirs := []string{filepath.Join(wd, ".runeward")}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "runeward"))
	} else if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".config", "runeward"))
	}
	return dirs
}

func isProfileExt(ext string) bool {
	for _, e := range profileExts {
		if ext == e {
			return true
		}
	}
	return false
}

func parseFile(path, name string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %q: %w", path, err)
	}
	var p Profile
	switch filepath.Ext(path) {
	case ".toml":
		dec := toml.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("parse profile %q: %w", path, err)
		}
	default:
		// sigs.k8s.io/yaml decodes via the json tags and handles .json too
		// (JSON is valid YAML). Strict mode rejects unknown fields, matching
		// TOML's DisallowUnknownFields.
		if err := yaml.UnmarshalStrict(data, &p); err != nil {
			return nil, fmt.Errorf("parse profile %q: %w", path, err)
		}
	}
	p.Name = name
	p.Source = path
	applyDefaults(&p)
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile %q: %w", path, err)
	}
	return &p, nil
}

func applyDefaults(p *Profile) {
	if p.Host.Type == "" {
		p.Host.Type = HostContainer
	}
	if p.Host.Workdir == "" {
		p.Host.Workdir = "/workspace"
	}
	if p.Host.Image == "" {
		p.Host.Image = "ghcr.io/adefemi171/runeward-sandbox:latest"
	}
}

func validateName(name string) error {
	if name == "" {
		return errors.New("empty profile name")
	}
	// Guard against path traversal in profile names.
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return fmt.Errorf("invalid profile name %q", name)
	}
	return nil
}

// Validate checks cross-field invariants after parsing.
func (p *Profile) Validate() error {
	switch p.Host.Type {
	case HostContainer, HostK8s:
	default:
		return fmt.Errorf("unsupported host.type %q (want %q or %q)", p.Host.Type, HostContainer, HostK8s)
	}
	if d := p.Network.Default; d != "" && d != "allow" && d != "deny" {
		return fmt.Errorf("network.default must be \"allow\" or \"deny\", got %q", d)
	}
	for i, e := range p.Env {
		if e.Name == "" {
			return fmt.Errorf("env[%d]: missing name", i)
		}
		set := 0
		if e.Value != "" {
			set++
		}
		if e.File != "" {
			set++
		}
		if e.Op != "" {
			set++
		}
		if set > 1 {
			return fmt.Errorf("env[%d] (%s): set only one of value/file/op", i, e.Name)
		}
	}
	for i, r := range p.Policy {
		switch r.Verdict {
		case VerdictAllow, VerdictDeny, VerdictRequireApprove:
		default:
			return fmt.Errorf("policy[%d]: invalid verdict %q", i, r.Verdict)
		}
	}
	switch p.PolicyEngine {
	case "", "builtin", "cel", "rego":
	default:
		return fmt.Errorf("policy_engine must be \"builtin\", \"cel\", or \"rego\", got %q", p.PolicyEngine)
	}
	if p.PolicyEngine == "rego" {
		set := 0
		if p.Rego.Module != "" {
			set++
		}
		if p.Rego.File != "" {
			set++
		}
		if set != 1 {
			return fmt.Errorf("rego: set exactly one of module/file")
		}
	}
	for i, r := range p.CEL {
		switch r.Verdict {
		case "", VerdictAllow, VerdictDeny, VerdictRequireApprove:
		default:
			return fmt.Errorf("cel[%d]: invalid verdict %q", i, r.Verdict)
		}
	}
	if p.UsesPolicyBundle() {
		if p.PolicyBundle.Ref == "" {
			return fmt.Errorf("policy_bundle: ref is required")
		}
		if k := p.PolicyBundle.VerifyKey; k != "" {
			b, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				return fmt.Errorf("policy_bundle.verify_key: not valid base64: %w", err)
			}
			if len(b) != ed25519.PublicKeySize {
				return fmt.Errorf("policy_bundle.verify_key: wrong ed25519 public key size %d (want %d)", len(b), ed25519.PublicKeySize)
			}
		}
	}
	if p.Fleet != nil && p.Fleet.Replicas < 0 {
		return fmt.Errorf("fleet.replicas must be >= 0")
	}
	return nil
}
