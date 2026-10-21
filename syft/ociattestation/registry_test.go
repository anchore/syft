package ociattestation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

func TestNewClientForImageUsesResolvedDigest(t *testing.T) {
	f := newRegistryFixture()
	f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"openssl","version":"1.0","type":"library"}]}`))
	srv := f.server(t)
	// HTTPS is not required by the local test registry; production defaults to HTTPS.
	reference := strings.TrimPrefix(srv.URL, "http://") + "/org/repo:latest"
	meta := source.Description{Metadata: source.ImageMetadata{ManifestDigest: testImageSHA}}
	regOpts := &image.RegistryOptions{InsecureUseHTTP: true}
	client, digest, err := NewClientForImage(context.Background(), reference, meta, regOpts)
	if err != nil {
		t.Fatal(err)
	}
	if digest != testImageSHA {
		t.Fatalf("digest %q differs from resolved image", digest)
	}
	if client.Repository != "org/repo" || client.BaseURL != srv.URL {
		t.Fatalf("unexpected registry location: %q / %q", client.Repository, client.BaseURL)
	}
	results, err := client.Discover(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one attested SBOM, got %d", len(results))
	}
	imported, err := Import(context.Background(), reference, meta, regOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 || imported[0].Document.Artifacts.Packages.PackageCount() != 1 {
		t.Fatalf("unexpected decoded inventory: %+v", imported)
	}
}

func TestNewClientForImageRejectsInvalidInputs(t *testing.T) {
	validMeta := source.Description{Metadata: source.ImageMetadata{ManifestDigest: testImageSHA}}
	opts := &image.RegistryOptions{InsecureUseHTTP: true}
	for _, tc := range []struct {
		name   string
		ref    string
		source source.Description
	}{
		{"non-image", "localhost:5000/org/repo:latest", source.Description{}},
		{"bad resolved digest", "localhost:5000/org/repo:latest", source.Description{Metadata: source.ImageMetadata{ManifestDigest: "sha256:malformed"}}},
		{"bad registry reference", "invalid reference with spaces", validMeta},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := NewClientForImage(context.Background(), tc.ref, tc.source, opts); err == nil {
				t.Fatal("expected invalid metadata/reference error")
			}
		})
	}
}

func TestNewClientForImageWithBasicAuthChallenge(t *testing.T) {
	fixture := newRegistryFixture()
	fixture.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"library","name":"private-lib","version":"1.0"}]}`))
	const username, password = "reader", "do-not-log-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="test-registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/v2/org/repo/referrers/"+testImageSHA {
			_, _ = w.Write(encodeJSON(t, fixture.idx))
			return
		}
		if data, found := fixture.blobs[r.URL.Path]; found {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	authority := strings.TrimPrefix(srv.URL, "http://")
	imageRef := authority + "/org/repo:latest"
	description := source.Description{Metadata: source.ImageMetadata{ManifestDigest: testImageSHA}}
	options := &image.RegistryOptions{InsecureUseHTTP: true, Credentials: []image.RegistryCredentials{{
		Authority: authority,
		Username:  username,
		Password:  password,
	}}}
	result, err := Import(context.Background(), imageRef, description, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Document.Artifacts.Packages.PackageCount() != 1 {
		t.Fatalf("authenticated import: expected 1 SBOM with one package, got %+v", result)
	}
}

func TestImportVerificationRequiresAnAttestedSBOM(t *testing.T) {
	fixture := newRegistryFixture()
	srv := fixture.server(t)
	ref := strings.TrimPrefix(srv.URL, "http://") + "/org/repo:latest"
	meta := source.Description{Metadata: source.ImageMetadata{ManifestDigest: testImageSHA}}
	opts := &image.RegistryOptions{InsecureUseHTTP: true}
	withoutVerification, err := Import(context.Background(), ref, meta, opts)
	if err != nil || len(withoutVerification) != 0 {
		t.Fatalf("empty unsigned additive import must be unchanged, got %+v: %v", withoutVerification, err)
	}
	check := &stubSigstoreVerifier{}
	_, err = Import(context.Background(), ref, meta, opts, check)
	if err == nil || !strings.Contains(err.Error(), "no verified OCI-attested SBOM") {
		t.Fatalf("signed-SBOM requirement silently ignored: %v", err)
	}
	if check.calls != 0 {
		t.Fatalf("verifier called without an attestation: %d", check.calls)
	}
}
