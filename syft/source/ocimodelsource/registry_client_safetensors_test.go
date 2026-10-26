package ocimodelsource

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/source"
)

func TestDetectModelFormat(t *testing.T) {
	tests := []struct {
		name        string
		gguf        int
		safetensors int
		expected    string
	}{
		{name: "gguf only", gguf: 2, safetensors: 0, expected: modelFormatGGUF},
		{name: "safetensors only", gguf: 0, safetensors: 3, expected: modelFormatSafeTensors},
		{name: "both prefers gguf", gguf: 1, safetensors: 1, expected: modelFormatGGUF},
		{name: "neither", gguf: 0, safetensors: 0, expected: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, detectModelFormat(test.gguf, test.safetensors))
		})
	}
}

func TestExtractSafeTensorsLayers(t *testing.T) {
	manifest := &v1.Manifest{Layers: []v1.Descriptor{
		{MediaType: types.MediaType(safetensorsLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "a"}},
		{MediaType: types.MediaType(ggufLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "b"}},
		{MediaType: types.MediaType(safetensorsLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "c"}},
	}}
	assert.Len(t, extractSafeTensorsLayers(manifest), 2)
}

func TestExtractCompanionLayers(t *testing.T) {
	manifest := &v1.Manifest{Layers: []v1.Descriptor{
		{MediaType: types.MediaType(modelFileMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "readme"}},
		{MediaType: types.MediaType(licenseMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "license"}},
		{MediaType: types.MediaType(safetensorsLayerMediaType), Digest: v1.Hash{Algorithm: "sha256", Hex: "weights"}},
		{MediaType: types.DockerLayer, Digest: v1.Hash{Algorithm: "sha256", Hex: "other"}},
	}}
	// only the model.file and license layers should be selected (not weights or arbitrary layers)
	assert.Len(t, extractCompanionLayers(manifest), 2)
}

func TestCalculateTotalSize(t *testing.T) {
	layers := []source.LayerMetadata{{Size: 100}, {Size: 250}, {Size: 0}}
	assert.Equal(t, int64(350), calculateTotalSize(layers))
}
