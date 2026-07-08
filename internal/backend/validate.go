package backend

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Runewardd/runeward/internal/egress"
)

// copyFromRootsEnv names an optional colon-separated allowlist of directory
// roots that `copy_from`/SeedDir sources must live under. When unset, any
// readable directory is permitted (backward compatible); operators running the
// API beyond a trusted machine should set it to confine the host-file read.
const copyFromRootsEnv = "RUNEWARD_COPY_FROM_ROOTS"

// validateSeedDir enforces the copy_from allowlist. srcDir is the (home-
// expanded) source directory. When RUNEWARD_COPY_FROM_ROOTS is set, srcDir —
// resolved through symlinks — must be one of the roots or nested under it, so a
// crafted path or symlink can't read outside the allowed tree.
func validateSeedDir(srcDir string) error {
	roots := strings.TrimSpace(os.Getenv(copyFromRootsEnv))
	if roots == "" {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		// Fall back to a lexical clean if the path can't be resolved (e.g. it
		// doesn't exist yet); the caller's existence check will surface that.
		resolved = filepath.Clean(srcDir)
	}
	for _, root := range strings.Split(roots, string(os.PathListSeparator)) {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		rr, err := filepath.EvalSymlinks(root)
		if err != nil {
			rr = filepath.Clean(root)
		}
		if resolved == rr || strings.HasPrefix(resolved, rr+string(os.PathSeparator)) {
			return nil
		}
	}
	return fmt.Errorf("copy_from %q is outside the allowed roots (%s=%s)", srcDir, copyFromRootsEnv, roots)
}

// fileModeRE matches a 3- or 4-digit octal file mode (e.g. "0644", "755").
var fileModeRE = regexp.MustCompile(`^[0-7]{3,4}$`)

// envNameRE matches a POSIX-portable environment variable name.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateFileMode rejects a mode that isn't plain octal, so a value like
// "644; rm -rf /" can't be interpolated into a shell `chmod`.
func validateFileMode(mode string) error {
	if mode == "" {
		return nil
	}
	if !fileModeRE.MatchString(mode) {
		return fmt.Errorf("invalid file mode %q: want 3-4 octal digits", mode)
	}
	return nil
}

// validateEnvName rejects env variable names that aren't identifier-safe, so a
// crafted name can't break out of a shell `export`.
func validateEnvName(name string) error {
	if !envNameRE.MatchString(name) {
		return fmt.Errorf("invalid environment variable name %q", name)
	}
	return nil
}

// confineFilesEnv, when truthy, restricts [[file]] projection targets to
// workspace-relative paths (no absolute targets), confining writes to the
// sandbox workdir. Off by default because absolute dotfile targets (e.g.
// /root/.gitconfig) are a common, legitimate use.
const confineFilesEnv = "RUNEWARD_CONFINE_FILES"

// validateProjectionPath rejects file-projection targets that use ".."
// traversal, so a profile can't escape the intended tree. Absolute paths are
// allowed by default (dotfiles commonly live at absolute locations), but path
// elements that climb out ("..") are refused. When RUNEWARD_CONFINE_FILES is
// set, absolute targets are refused too, confining projections to the workdir.
func validateProjectionPath(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("file projection path is empty")
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return fmt.Errorf("file projection path %q escapes with '..'", p)
	}
	if confineFilesEnabled() && path.IsAbs(clean) {
		return fmt.Errorf("file projection path %q is absolute but %s confines projections to the workspace", p, confineFilesEnv)
	}
	return nil
}

// confineFilesEnabled reports whether absolute file projections are forbidden.
func confineFilesEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(confineFilesEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// validateStrictEgressUser rejects sandbox users that collide with the strict
// egress proxy uid. iptables exempts that uid to avoid proxy self-redirection,
// so allowing the sandbox to run as it would bypass strict interception.
func validateStrictEgressUser(spec Spec) error {
	if !spec.Network.StrictEgress() {
		return nil
	}
	uid, ok := numericUID(spec.User)
	if !ok {
		return nil
	}
	if uid == egress.StrictProxyUID {
		return fmt.Errorf("host.user uid %d is reserved for strict egress and cannot be used when network.enforce=strict", egress.StrictProxyUID)
	}
	return nil
}

func numericUID(user string) (int, bool) {
	u := strings.TrimSpace(user)
	if u == "" {
		return 0, false
	}
	if i := strings.Index(u, ":"); i >= 0 {
		u = u[:i]
	}
	if u == "" {
		return 0, false
	}
	for _, r := range u {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	id, err := strconv.Atoi(u)
	if err != nil {
		return 0, false
	}
	return id, true
}
