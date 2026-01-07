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
