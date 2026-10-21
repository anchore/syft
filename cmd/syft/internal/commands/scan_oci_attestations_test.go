package commands

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source"
)

const testResolvedImageDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestProduceScanSBOMRejectsUnknownMode(t *testing.T) {
	opts := defaultScanOptions()
	opts.AttestedSBOM = "unknown"
	src := source.FromDescription(source.Description{Name: "test"})
	_, err := produceScanSBOM(context.Background(), clio.Identification{}, src, opts, "example.test/image:latest")
	if err == nil || !strings.Contains(err.Error(), "invalid --attested-sbom") {
		t.Fatalf("expected helpful mode error, got %v", err)
	}
}

func TestProduceScanSBOMReplacementDoesNotSilentlyFallBackToScan(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(registry.Close)
	imageRef := strings.TrimPrefix(registry.URL, "http://") + "/org/repo:latest"
	src := source.FromDescription(source.Description{
		Name:     imageRef,
		Metadata: source.ImageMetadata{ManifestDigest: testResolvedImageDigest, UserInput: imageRef},
	})
	opts := defaultScanOptions()
	opts.Registry.InsecureUseHTTP = true
	opts.AttestedSBOM = "replacement"
	_, err := produceScanSBOM(context.Background(), clio.Identification{Name: "syft"}, src, opts, imageRef, "registry")
	if err == nil || !strings.Contains(err.Error(), "no usable attested SBOM") {
		t.Fatalf("replacement must fail if registry has no SBOM; got %v", err)
	}
}

func TestProduceScanSBOMRejectsNonImageSources(t *testing.T) {
	opts := defaultScanOptions()
	opts.AttestedSBOM = "replacement"
	src := source.FromDescription(source.Description{Name: "filesystem"})
	_, err := produceScanSBOM(context.Background(), clio.Identification{Name: "syft"}, src, opts, "dir:/example", "registry")
	if err == nil || !strings.Contains(err.Error(), "container images") {
		t.Fatalf("expected image-only validation, got %v", err)
	}
}

func TestProduceScanSBOMRequiresExplicitRegistrySource(t *testing.T) {
	opts := defaultScanOptions()
	opts.AttestedSBOM = "replacement"
	src := source.FromDescription(source.Description{
		Name:     "docker-daemon-image",
		Metadata: source.ImageMetadata{ManifestDigest: testResolvedImageDigest},
	})
	for _, candidate := range []string{"docker:example.org/image:latest", "example.org/image:latest"} {
		_, err := produceScanSBOM(context.Background(), clio.Identification{Name: "syft"}, src, opts, candidate)
		if err == nil || !strings.Contains(err.Error(), "requires an explicit registry source") {
			t.Fatalf("input %q should reject implicit/daemon registry access: %v", candidate, err)
		}
	}
}

func TestAttestedSBOMVerificationPolicyIsFailClosed(t *testing.T) {
	src := source.FromDescription(source.Description{Name: "local"})
	for _, tc := range []struct {
		name     string
		mode     string
		verify   bool
		issuer   string
		identity string
		want     string
	}{
		{"cannot verify disabled import", "off", true, "issuer", "identity", "require --attested-sbom"},
		{"missing issuer", "replacement", true, "", "identity", "requires both"},
		{"missing identity", "additive", true, "issuer", "", "requires both"},
		{"cannot provide identity without verification", "additive", false, "", "identity", "require --attested-sbom-verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := defaultScanOptions()
			opts.AttestedSBOM = tc.mode
			opts.AttestedSBOMVerify = tc.verify
			opts.AttestedSBOMIssuer = tc.issuer
			opts.AttestedSBOMIdentity = tc.identity
			_, err := produceScanSBOM(context.Background(), clio.Identification{}, src, opts, "example.org/image", "registry")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected configuration error containing %q, got %v", tc.want, err)
			}
		})
	}
}
