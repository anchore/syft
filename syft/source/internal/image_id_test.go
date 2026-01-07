package internal

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

func TestDeriveImageID(t *testing.T) {
	tests := []struct {
		name     string
		alias    source.Alias
		metadata source.ImageMetadata
		want     artifact.ID
	}{
		{
			name: "use raw manifest over chain ID or user input",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
				RawManifest: []byte("raw-manifest"),
			},
			want: func() artifact.ID {
				hasher := sha256.New()
				hasher.Write([]byte("raw-manifest"))
				return artifact.ID(fmt.Sprintf("%x", hasher.Sum(nil)))
			}(),
		},
		{
			name: "use chain ID over user input",
			metadata: source.ImageMetadata{
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
			},
			want: func() artifact.ID {
				metadata := []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				}
				return artifact.ID(strings.TrimPrefix(calculateChainID(metadata), "sha256:"))
			}(),
		},
		{
			name: "use user input last",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
			},
			want: func() artifact.ID {
				hasher := sha256.New()
				hasher.Write([]byte("user-input"))
				return artifact.ID(fmt.Sprintf("%x", hasher.Sum(nil)))
			}(),
		},
		{
			name: "without alias (first)",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
				RawManifest: []byte("raw-manifest"),
			},
			want: "85298926ecd92ed57688f13039017160cd728f04dd0d2d10a10629007106f107",
		},
		{
			name: "always consider alias (first)",
			alias: source.Alias{
				Name:    "alias",
				Version: "version",
			},
			metadata: source.ImageMetadata{
				UserInput: "user-input",
				Layers: []source.LayerMetadata{
					{
						Digest: "a",
					},
					{
						Digest: "b",
					},
					{
						Digest: "c",
					},
				},
				RawManifest: []byte("raw-manifest"),
			},
			want: "a8717e42449960c1dd4963f2f22bd69c7c105e7e82445be0a65aa1825d62ff0d",
		},
		{
			name: "without alias (last)",
			metadata: source.ImageMetadata{
				UserInput: "user-input",
			},
			want: "ab0dff627d80b9753193d7280bec8f45e8ec6b4cb0912c6fffcf7cd782d9739e",
		},
		{
			name: "always consider alias (last)",
			alias: source.Alias{
				Name:    "alias",
				Version: "version",
			},
			metadata: source.ImageMetadata{
				UserInput: "user-input",
			},
			want: "fe86c0eecd5654d3c0c0b2176aa394aef6440347c241aa8d9b628dfdde4287cf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, DeriveImageID(tt.alias, tt.metadata))
		})
	}
}

// ensures same metadata produces identical IDs
// regardless of whether the source is stereoscope-based or OCI model-based. Both source types
// use DeriveImageID with ImageMetadata
// this test captures known-good IDs that must remain
// stable across refactors to maintain consistency.
//
// IMPORTANT: If any of these tests fail after a refactor, it means the artifact ID generation
// has changed and will break consistency between stereoscope images and OCI model sources.
func TestDeriveImageID_CrossSourceConsistency(t *testing.T) {
	tests := []struct {
		name     string
		alias    source.Alias
		metadata source.ImageMetadata
		wantID   artifact.ID
	}{
		{
			name: "raw manifest with layers - typical container image",
			metadata: source.ImageMetadata{
				UserInput:      "docker.io/library/alpine:latest",
				ManifestDigest: "sha256:abc123",
				Layers: []source.LayerMetadata{
					{Digest: "sha256:layer1", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Size: 1000},
					{Digest: "sha256:layer2", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Size: 2000},
				},
				RawManifest: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`),
			},
			// snapshot: this ID must remain stable for stereoscope/oci-model consistency
			wantID: "b22c7289dd3b4785a3795c90e15d16bd66bd29b444b8974fe29ed0443ce50405",
		},
		{
			name: "raw manifest only - minimal image",
			metadata: source.ImageMetadata{
				RawManifest: []byte(`{"schemaVersion":2}`),
			},
			// snapshot: this ID must remain stable
			wantID: "bafebd36189ad3688b7b3915ea55d461e0bfcfbdde11e54b0a123999fb6be50f",
		},
		{
			name: "chain ID fallback - no raw manifest",
			metadata: source.ImageMetadata{
				UserInput: "some-image",
				Layers: []source.LayerMetadata{
					{Digest: "sha256:aaa111"},
					{Digest: "sha256:bbb222"},
				},
			},
			// snapshot: chain ID calculation must remain stable
			wantID: "0ba9c8d271e6708871505d362e37267c5fb7910066c04d3115b89ba4d34aa180",
		},
		{
			name: "user input fallback - no manifest or layers",
			metadata: source.ImageMetadata{
				UserInput: "registry.example.com/org/model:v1.0",
			},
			// snapshot: user input hash must remain stable
			wantID: "a5a8733a3ba3eb99a8ebebcd40c4053f9b896ea6e2217ebc6e885573f20baccf",
		},
		{
			name: "with alias - same image different logical identity",
			alias: source.Alias{
				Name:    "my-custom-name",
				Version: "1.0.0",
			},
			metadata: source.ImageMetadata{
				RawManifest: []byte(`{"schemaVersion":2}`),
			},
			// snapshot: alias must affect ID deterministically
			wantID: "9eae41c0efc30023368c29089bac007f2c9d0b40a0ee034081a17c4c22f55ac6",
		},
		{
			name: "annotations has no effect on ID",
			metadata: source.ImageMetadata{
				UserInput: "registry.example.com/org/model:v1.0",
				Annotations: map[string]string{
					"annotation1": "value1",
				},
			},
			// snapshot: user input hash must remain stable
			wantID: "a5a8733a3ba3eb99a8ebebcd40c4053f9b896ea6e2217ebc6e885573f20baccf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveImageID(tt.alias, tt.metadata)
			assert.Equal(t, tt.wantID, got, "ID must remain stable for cross-source consistency")
		})
	}
}

func TestCalculateChainID(t *testing.T) {
	tests := []struct {
		name   string
		layers []source.LayerMetadata
		want   string
	}{
		{
			name:   "empty layers returns empty string",
			layers: []source.LayerMetadata{},
			want:   "",
		},
		{
			name: "single layer returns digest",
			layers: []source.LayerMetadata{
				{Digest: "sha256:abc123"},
			},
			want: "sha256:abc123",
		},
		{
			name: "multiple layers calculates chain ID",
			layers: []source.LayerMetadata{
				{Digest: "a"},
				{Digest: "b"},
				{Digest: "c"},
			},
			// snapshot - this value should not change
			want: "sha256:1dfe230e220ef0e6bc0a8978d23d72b95769e76a62879a5f49267d8c007ab43d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, calculateChainID(tt.layers))
		})
	}
}
