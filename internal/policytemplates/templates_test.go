package policytemplates

import (
	"sort"
	"strings"
	"testing"

	"github.com/Runewardd/runeward/internal/profile"
	toml "github.com/pelletier/go-toml/v2"
)

// TestRenderUnmarshalsStrict proves every template is valid profile TOML with
// no typo'd keys: a strict decoder (DisallowUnknownFields) must accept it.
func TestRenderUnmarshalsStrict(t *testing.T) {
	for _, name := range Names() {
		name := name
		t.Run(name, func(t *testing.T) {
			body, err := Render(name)
			if err != nil {
				t.Fatalf("Render(%q) returned error: %v", name, err)
			}
			if strings.TrimSpace(body) == "" {
				t.Fatalf("Render(%q) returned empty body", name)
			}

			var p profile.Profile
			dec := toml.NewDecoder(strings.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				t.Fatalf("template %q does not decode strictly into profile.Profile: %v\n---\n%s", name, err, body)
			}
		})
	}
}

// TestGetMatchesRender ensures Get and Render agree and expose the same body.
func TestGetMatchesRender(t *testing.T) {
	for _, name := range Names() {
		tmpl, ok := Get(name)
		if !ok {
			t.Fatalf("Get(%q) reported missing template", name)
		}
		if tmpl.Name != name {
			t.Fatalf("Get(%q).Name = %q, want %q", name, tmpl.Name, name)
		}
		if tmpl.Title == "" || tmpl.Description == "" {
			t.Fatalf("template %q missing Title/Description", name)
		}
		body, err := Render(name)
		if err != nil {
			t.Fatalf("Render(%q): %v", name, err)
		}
		if body != tmpl.TOML {
			t.Fatalf("Render(%q) body differs from Get(%q).TOML", name, name)
		}
	}
}

func TestNamesSorted(t *testing.T) {
	names := Names()
	if len(names) < 5 {
		t.Fatalf("expected at least 5 templates, got %d: %v", len(names), names)
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("Names() is not sorted: %v", names)
	}
}

func TestGetUnknown(t *testing.T) {
	if _, ok := Get("does-not-exist"); ok {
		t.Fatal("Get returned ok for an unknown template name")
	}
	if _, err := Render("does-not-exist"); err == nil {
		t.Fatal("Render returned nil error for an unknown template name")
	}
}

func TestAllCoversRegistry(t *testing.T) {
	all := All()
	if len(all) != len(Names()) {
		t.Fatalf("All() returned %d templates, Names() has %d", len(all), len(Names()))
	}
	for i, tmpl := range all {
		if i > 0 && all[i-1].Name >= tmpl.Name {
			t.Fatalf("All() is not sorted by Name: %q before %q", all[i-1].Name, tmpl.Name)
		}
	}

	// The specific templates the package is required to ship.
	want := []string{
		"block-prod",
		"least-privilege-egress",
		"package-approval",
		"pii-egress",
		"read-only-fs",
	}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v", got, want)
		}
	}
}

func TestBlockProdEgressOrderingGuidanceMatchesEngine(t *testing.T) {
	body, err := Render("block-prod")
	if err != nil {
		t.Fatalf("Render(block-prod): %v", err)
	}
	if strings.Contains(body, "Deny rules are evaluated\n# before any allow rules") {
		t.Fatalf("block-prod contains deny-precedence wording that does not match first-match egress behavior")
	}
	if !strings.Contains(body, "Egress rules are first-match") {
		t.Fatalf("block-prod should document first-match egress ordering")
	}
}
