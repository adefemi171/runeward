package policybundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/content/oci"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func regoBundle() *Bundle {
	return &Bundle{
		Engine: EngineRego,
		Query:  "data.runeward.decision",
		Policy: []byte("package runeward\n\ndecision := \"allow\"\n"),
	}
}

func celBundle() *Bundle {
	return &Bundle{
		Engine: EngineCEL,
		Policy: []byte("[[cel]]\nexpr = 'tool == \"shell\"'\nverdict = \"deny\"\nreason = \"no shell\"\n"),
	}
}

func roundTrip(t *testing.T, b *Bundle, priv ed25519.PrivateKey, verify ed25519.PublicKey) (*Bundle, error) {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	if _, err := pushTo(ctx, store, "v1", b, priv); err != nil {
		t.Fatalf("push: %v", err)
	}
	return pullFrom(ctx, store, "v1", verify)
}

func TestRoundTripRego(t *testing.T) {
	pub, priv := newKey(t)
	src := regoBundle()
	got, err := roundTrip(t, src, priv, pub)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got.Engine != EngineRego {
		t.Errorf("engine = %q, want %q", got.Engine, EngineRego)
	}
	if got.Query != src.Query {
		t.Errorf("query = %q, want %q", got.Query, src.Query)
	}
	if string(got.Policy) != string(src.Policy) {
		t.Errorf("policy = %q, want %q", got.Policy, src.Policy)
	}
}

func TestRoundTripCEL(t *testing.T) {
	pub, priv := newKey(t)
	src := celBundle()
	got, err := roundTrip(t, src, priv, pub)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got.Engine != EngineCEL {
		t.Errorf("engine = %q, want %q", got.Engine, EngineCEL)
	}
	if string(got.Policy) != string(src.Policy) {
		t.Errorf("policy = %q, want %q", got.Policy, src.Policy)
	}
}

func TestPullNilVerifySucceedsUnsigned(t *testing.T) {
	_, priv := newKey(t)
	got, err := roundTrip(t, regoBundle(), priv, nil)
	if err != nil {
		t.Fatalf("pull with nil verify: %v", err)
	}
	if got.Engine != EngineRego {
		t.Errorf("engine = %q, want %q", got.Engine, EngineRego)
	}
}

func TestPullWrongKeyFails(t *testing.T) {
	_, priv := newKey(t)
	wrongPub, _ := newKey(t)
	if _, err := roundTrip(t, regoBundle(), priv, wrongPub); err == nil {
		t.Fatal("expected verification to fail with the wrong public key")
	}
}

// TestTamperedPolicyFails repoints the manifest's layer descriptor at a
// tampered blob; the signature covers the original digest, so a verifying
// pull must fail closed.
func TestTamperedPolicyFails(t *testing.T) {
	ctx := context.Background()
	pub, priv := newKey(t)
	store := memory.New()

	src := regoBundle()
	if _, err := pushTo(ctx, store, "v1", src, priv); err != nil {
		t.Fatalf("push: %v", err)
	}

	_, manifestBytes, err := oras.FetchBytes(ctx, store, "v1", oras.DefaultFetchBytesOptions)
	if err != nil {
		t.Fatalf("fetch original manifest: %v", err)
	}
	var orig ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &orig); err != nil {
		t.Fatalf("decode original manifest: %v", err)
	}

	// Re-pack a manifest with the original signature annotations and config
	// but a tampered layer.
	tampered := []byte("package runeward\n\ndecision := \"deny\"\n")
	layerDesc, err := oras.PushBytes(ctx, store, MediaTypeLayerRego, tampered)
	if err != nil {
		t.Fatalf("push tampered layer: %v", err)
	}
	forged, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{
		ConfigDescriptor:    &orig.Config,
		Layers:              []ocispec.Descriptor{layerDesc},
		ManifestAnnotations: orig.Annotations,
	})
	if err != nil {
		t.Fatalf("pack forged: %v", err)
	}
	if err := store.Tag(ctx, forged, "forged"); err != nil {
		t.Fatalf("tag forged: %v", err)
	}

	if _, err := pullFrom(ctx, store, "forged", pub); err == nil {
		t.Fatal("expected verification to fail for a tampered policy layer")
	}
}

func TestOCILayoutRoundTrip(t *testing.T) {
	ctx := context.Background()
	pub, priv := newKey(t)
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("oci store: %v", err)
	}
	src := celBundle()
	if _, err := pushTo(ctx, store, "v2", src, priv); err != nil {
		t.Fatalf("push: %v", err)
	}
	got, err := pullFrom(ctx, store, "v2", pub)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got.Engine != EngineCEL || string(got.Policy) != string(src.Policy) {
		t.Errorf("round-trip mismatch: engine=%q policy=%q", got.Engine, got.Policy)
	}
}
