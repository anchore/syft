package ociattestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testImageSHA = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func encodeJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contentDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type registryFixture struct {
	idx    index
	blobs  map[string][]byte
	status map[string]int
}

func newRegistryFixture() *registryFixture {
	return &registryFixture{blobs: make(map[string][]byte), status: make(map[string]int)}
}

func (f *registryFixture) addSBOM(t *testing.T, subjectDigest, predType string, doc []byte) {
	t.Helper()
	payload := encodeJSON(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predType,
		"subject":       []any{map[string]any{"name": "example.org/test", "digest": map[string]string{"sha256": strings.TrimPrefix(subjectDigest, "sha256:")}}},
		"predicate":     json.RawMessage(doc),
	})
	bundleBytes := encodeJSON(t, map[string]any{"dsseEnvelope": map[string]string{
		"payload": base64.StdEncoding.EncodeToString(payload), "payloadType": DSSEPayloadType,
	}})
	layerHash := contentDigest(bundleBytes)
	f.blobs["/v2/org/repo/blobs/"+layerHash] = bundleBytes
	m := encodeJSON(t, manifest{
		MediaType: ManifestMediaType, ArtifactType: BundleMediaType,
		Subject: &descriptor{Digest: subjectDigest},
		Layers:  []descriptor{{MediaType: BundleMediaType, Digest: layerHash, Size: int64(len(bundleBytes))}},
	})
	mHash := contentDigest(m)
	f.blobs["/v2/org/repo/manifests/"+mHash] = m
	f.idx.Manifests = append(f.idx.Manifests, descriptor{
		MediaType: ManifestMediaType, ArtifactType: BundleMediaType, Digest: mHash, Size: int64(len(m)),
		Annotations: map[string]string{"dev.sigstore.bundle.content": "dsse-envelope", "dev.sigstore.bundle.predicateType": predType},
	})
}

func (f *registryFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if code, ok := f.status[r.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		if r.URL.Path == "/v2/org/repo/referrers/"+testImageSHA {
			_, _ = w.Write(encodeJSON(t, f.idx))
			return
		}
		if data, ok := f.blobs[r.URL.Path]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fixtureClient(srv *httptest.Server) *Client {
	return &Client{BaseURL: srv.URL, Repository: "org/repo", HTTPClient: srv.Client()}
}

func TestDiscoverCycloneDXAndSPDX(t *testing.T) {
	f := newRegistryFixture()
	f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"log4j-core","version":"2.14.1"}]}`))
	f.addSBOM(t, testImageSHA, SPDXPredicate, []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"log4j-core","versionInfo":"2.14.1"}]}`))
	got, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 SBOMs, got %d", len(got))
	}
	if got[0].Format != "cyclonedx-json" || got[1].Format != "spdx-json" {
		t.Fatalf("unexpected formats: %+v", got)
	}
	if !bytes.Contains(got[0].Document, []byte("log4j-core")) {
		t.Fatal("SBOM content missing")
	}
	if got[0].SignatureVerified || got[1].SignatureVerified {
		t.Fatal("must not claim signature verification")
	}
}

func TestDiscoverAbsentAndUnrelated(t *testing.T) {
	t.Run("404", func(t *testing.T) {
		f := newRegistryFixture()
		f.status["/v2/org/repo/referrers/"+testImageSHA] = http.StatusNotFound
		got, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v err %v", got, err)
		}
	})
	t.Run("non-SBOM", func(t *testing.T) {
		f := newRegistryFixture()
		f.idx.Manifests = []descriptor{{ArtifactType: "application/vnd.example.unrelated", Digest: testImageSHA}}
		got, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v err %v", got, err)
		}
	})
}

func TestDiscoverRejectsIntegrityViolations(t *testing.T) {
	t.Run("manifest content tampered", func(t *testing.T) {
		f := newRegistryFixture()
		f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX"}`))
		f.blobs["/v2/org/repo/manifests/"+f.idx.Manifests[0].Digest] = []byte(`{"tampered":true}`)
		_, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("expected digest mismatch, got %v", err)
		}
	})
	t.Run("manifest OCI subject differs", func(t *testing.T) {
		f := newRegistryFixture()
		f.addSBOM(t, "sha256:"+strings.Repeat("f", 64), CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX"}`))
		_, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err == nil || !strings.Contains(err.Error(), "not attached") {
			t.Fatalf("expected subject mismatch, got %v", err)
		}
	})
	t.Run("descriptor size tampered", func(t *testing.T) {
		f := newRegistryFixture()
		f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX"}`))
		f.idx.Manifests[0].Size--
		_, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err == nil || !strings.Contains(err.Error(), "size mismatch") {
			t.Fatalf("expected size mismatch, got %v", err)
		}
	})
}

func TestDiscoverRejectsInvalidSBOMAndInput(t *testing.T) {
	f := newRegistryFixture()
	f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"spdxVersion":"SPDX-2.3"}`))
	_, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
	if err == nil || !strings.Contains(err.Error(), "bomFormat") {
		t.Fatalf("expected bad CycloneDX, got %v", err)
	}
	t.Run("malformed image digest", func(t *testing.T) {
		c := fixtureClient(f.server(t))
		if _, err := c.Discover(context.Background(), "sha256:bad"); err == nil {
			t.Fatal("accepted malformed digest")
		}
	})
	t.Run("path traversal repository", func(t *testing.T) {
		c := fixtureClient(f.server(t))
		c.Repository = "org/../private"
		if _, err := c.Discover(context.Background(), testImageSHA); err == nil {
			t.Fatal("accepted path traversal")
		}
	})
	t.Run("credentialed URL", func(t *testing.T) {
		c := fixtureClient(f.server(t))
		c.BaseURL = "https://user:password@example.org"
		if _, err := c.Discover(context.Background(), testImageSHA); err == nil {
			t.Fatal("accepted userinfo")
		}
	})
}

func TestDiscoverResourceBudgetsAndCancellation(t *testing.T) {
	f := newRegistryFixture()
	f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX"}`))
	srv := f.server(t)
	for _, limit := range []struct {
		name  string
		apply func(*Client)
	}{
		{"index", func(c *Client) { c.IndexLimit = 10 }},
		{"manifest", func(c *Client) { c.ManifestLimit = 10 }},
		{"blob", func(c *Client) { c.BlobLimit = 10 }},
		{"total", func(c *Client) { c.TotalLimit = 10 }},
	} {
		t.Run(limit.name, func(t *testing.T) {
			c := fixtureClient(srv)
			limit.apply(c)
			if _, err := c.Discover(context.Background(), testImageSHA); err == nil {
				t.Fatal("accepted oversized content")
			}
		})
	}
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := fixtureClient(srv).Discover(ctx, testImageSHA); err == nil {
			t.Fatal("ignored cancellation")
		}
	})
}

func TestVersionedSPDXPredicates(t *testing.T) {
	t.Run("GitHub Actions SPDX v2.3", func(t *testing.T) {
		f := newRegistryFixture()
		f.addSBOM(t, testImageSHA, "https://spdx.dev/Document/v2.3", []byte("{\"spdxVersion\":\"SPDX-2.3\"}"))
		got, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err != nil || len(got) != 1 || got[0].PredicateType != SPDXPredicate {
			t.Fatalf("expected GitHub SPDX attestation: %v, %v", got, err)
		}
	})
	t.Run("SPDX v2.2", func(t *testing.T) {
		f := newRegistryFixture()
		f.addSBOM(t, testImageSHA, "https://spdx.dev/Document/v2.2", []byte("{\"spdxVersion\":\"SPDX-2.2\"}"))
		got, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err != nil || len(got) != 1 {
			t.Fatalf("expected versioned SPDX attestation: %v, %v", got, err)
		}
	})
	t.Run("rejects predicate and version mismatch", func(t *testing.T) {
		f := newRegistryFixture()
		f.addSBOM(t, testImageSHA, SPDXPredicate, []byte("{\"spdxVersion\":\"SPDX-2.2\"}"))
		_, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
		if err == nil || !strings.Contains(err.Error(), "spdxVersion") {
			t.Fatalf("expected mismatch rejection, got %v", err)
		}
	})
}

func TestDiscoverSkipsOrdinarySignatureBundles(t *testing.T) {
	for _, annotated := range []bool{true, false} {
		t.Run(fmt.Sprint("annotated=", annotated), func(t *testing.T) {
			f := newRegistryFixture()
			signature := encodeJSON(t, map[string]any{"messageSignature": map[string]any{"signature": "AA=="}})
			blobHash := contentDigest(signature)
			f.blobs["/v2/org/repo/blobs/"+blobHash] = signature
			m := manifest{
				MediaType:    ManifestMediaType,
				ArtifactType: BundleMediaType,
				Subject:      &descriptor{Digest: testImageSHA},
				Layers:       []descriptor{{MediaType: BundleMediaType, Digest: blobHash, Size: int64(len(signature))}},
			}
			desc := descriptor{ArtifactType: BundleMediaType, MediaType: ManifestMediaType}
			if annotated {
				m.Annotations = map[string]string{"dev.sigstore.bundle.content": "message-signature"}
				desc.Annotations = map[string]string{"dev.sigstore.bundle.content": "message-signature"}
			}
			rawManifest := encodeJSON(t, m)
			desc.Digest = contentDigest(rawManifest)
			desc.Size = int64(len(rawManifest))
			f.blobs["/v2/org/repo/manifests/"+desc.Digest] = rawManifest
			f.idx.Manifests = append(f.idx.Manifests, desc)
			f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\"}"))
			result, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
			if err != nil || len(result) != 1 {
				t.Fatalf("normal signatures must be ignored, got %d results: %v", len(result), err)
			}
		})
	}
}

func TestDiscoverReferrersTagFallback(t *testing.T) {
	f := newRegistryFixture()
	f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\"}"))
	f.status["/v2/org/repo/referrers/"+testImageSHA] = http.StatusNotFound
	tag := "sha256-" + strings.TrimPrefix(testImageSHA, "sha256:")
	f.blobs["/v2/org/repo/manifests/"+tag] = encodeJSON(t, f.idx)
	got, err := fixtureClient(f.server(t)).Discover(context.Background(), testImageSHA)
	if err != nil || len(got) != 1 {
		t.Fatalf("OCI fallback failed: %v, %v", got, err)
	}
}

type stubSigstoreVerifier struct {
	calls       int
	imageDigest string
	failure     error
}

func (v *stubSigstoreVerifier) VerifyBundle(bundleJSON []byte, digest string) error {
	v.calls++
	v.imageDigest = digest
	if len(bundleJSON) == 0 {
		return fmt.Errorf("missing signed bundle bytes")
	}
	return v.failure
}

func TestDiscoverCryptoVerificationIsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name            string
		verificationErr error
		wantVerified    bool
	}{
		{name: "valid signature and identity", wantVerified: true},
		{name: "invalid signature", verificationErr: fmt.Errorf("invalid DSSE signature")},
		{name: "untrusted signing identity", verificationErr: fmt.Errorf("untrusted Fulcio certificate identity")},
		{name: "missing Rekor inclusion proof", verificationErr: fmt.Errorf("missing Rekor inclusion proof")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegistryFixture()
			f.addSBOM(t, testImageSHA, CycloneDXPredicate, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`))
			v := &stubSigstoreVerifier{failure: tc.verificationErr}
			client := fixtureClient(f.server(t))
			client.BundleVerifier = v
			result, err := client.Discover(context.Background(), testImageSHA)
			if v.calls != 1 || v.imageDigest != testImageSHA {
				t.Fatalf("expected verifier bound to image digest: %+v", v)
			}
			if tc.verificationErr != nil {
				if err == nil || len(result) != 0 {
					t.Fatalf("expected fail-closed attestation rejection, got %+v err %v", result, err)
				}
				return
			}
			if err != nil || len(result) != 1 || !result[0].SignatureVerified {
				t.Fatalf("valid signature was not propagated, got %+v err %v", result, err)
			}
		})
	}
}
