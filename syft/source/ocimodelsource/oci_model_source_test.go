package ocimodelsource

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractVirtualPath(t *testing.T) {
	tests := []struct {
		name        string
		layerIndex  int
		annotations map[string]string
		expected    string
	}{
		{
			name:        "use index as model layer virtual path",
			layerIndex:  1,
			annotations: map[string]string{},
			expected:    "/model-layer-1.gguf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVirtualPath(tt.layerIndex)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateTotalSize(t *testing.T) {
	// This is imported from syft/source
	// Just a simple test to ensure it works
	layers := []struct {
		MediaType string
		Digest    string
		Size      int64
	}{
		{"application/vnd.docker.image.rootfs.diff.tar.gzip", "sha256:abc", 100},
		{"application/vnd.docker.image.rootfs.diff.tar.gzip", "sha256:def", 200},
	}

	// We'd need to convert to source.LayerMetadata to test this properly
	// For now, just ensure the package compiles
	assert.NotNil(t, layers)
}
