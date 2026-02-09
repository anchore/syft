package ocimodelsource

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
)

func TestIsModelArtifact(t *testing.T) {
	tests := []struct {
		name     string
		manifest *v1.Manifest
		expected bool
	}{
		{
			name: "valid model artifact",
			manifest: &v1.Manifest{
				Config: v1.Descriptor{
					MediaType: modelConfigMediaTypePrefix + "v1+json",
				},
			},
			expected: true,
		},
		{
			name: "container image",
			manifest: &v1.Manifest{
				Config: v1.Descriptor{
					MediaType: types.DockerConfigJSON,
				},
			},
			expected: false,
		},
		{
			name: "empty media type",
			manifest: &v1.Manifest{
				Config: v1.Descriptor{
					MediaType: "",
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isModelArtifact(test.manifest)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExtractGGUFLayers(t *testing.T) {
	tests := []struct {
		name     string
		manifest *v1.Manifest
		expected int
	}{
		{
			name: "single GGUF layer",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType(ggufLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "abc"}},
				},
			},
			expected: 1,
		},
		{
			name: "multiple GGUF layers",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType(ggufLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "abc"}},
					{MediaType: types.MediaType(ggufLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "def"}},
				},
			},
			expected: 2,
		},
		{
			name: "mixed layers",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType(ggufLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "abc"}},
					{MediaType: types.DockerLayer, Digest: v1.Hash{Algorithm: "sha256", Hex: "def"}},
					{MediaType: types.MediaType(ggufLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "ghi"}},
				},
			},
			expected: 2,
		},
		{
			name: "no GGUF layers",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: types.DockerLayer},
				},
			},
			expected: 0,
		},
		{
			name: "empty layers",
			manifest: &v1.Manifest{
				Layers: []v1.Descriptor{},
			},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractGGUFLayers(test.manifest)
			assert.Len(t, result, test.expected)
		})
	}
}
