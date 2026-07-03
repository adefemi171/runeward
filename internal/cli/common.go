package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/adefemi171/runeward/internal/profile"
)

// loadProfile resolves a profile by name, honoring --config-dir and
// $RUNEWARD_CONFIG_DIR.
func loadProfile(name string, configDir string) (*profile.Profile, error) {
	if configDir == "" {
		configDir = os.Getenv("RUNEWARD_CONFIG_DIR")
	}
	return profile.Load(name, profile.Options{ConfigDir: configDir})
}

// resolveEnv turns a profile's [[env]] entries into name=value pairs. Values
// are never written to disk; non-fatal problems come back as warnings.
func resolveEnv(p *profile.Profile) (map[string]string, []string) {
	out := make(map[string]string, len(p.Env))
	var warnings []string
	for _, e := range p.Env {
		switch {
		case e.Op != "":
			warnings = append(warnings, fmt.Sprintf("env %s: 1Password resolution (%s) not yet implemented; skipped", e.Name, e.Op))
		case e.File != "":
			b, err := os.ReadFile(expandHome(e.File))
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("env %s: read %s: %v; skipped", e.Name, e.File, err))
				continue
			}
			out[e.Name] = strings.TrimRight(string(b), "\r\n")
		case e.Value != "":
			out[e.Name] = e.Value
		}
	}
	return out, warnings
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}
