package fileresolver

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

const ggufLayerMediaType = "application/vnd.docker.ai.gguf.v3"

func TestOCIModelResolver_FilesByMediaType(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name       string
		layerFiles map[string]LayerInfo
		patterns   []string
		expected   int
	}{
		{
			name: "exact match GGUF",
			layerFiles: map[string]LayerInfo{
				"sha256:abc123": {TempPath: filepath.Join(tempDir, "f1"), MediaType: ggufLayerMediaType},
			},
			patterns: []string{ggufLayerMediaType},
			expected: 1,
		},
		{
			name: "glob match docker ai",
			layerFiles: map[string]LayerInfo{
				"sha256:abc123": {TempPath: filepath.Join(tempDir, "f1"), MediaType: ggufLayerMediaType},
			},
			patterns: []string{"application/vnd.docker.ai*"},
			expected: 1,
		},
		{
			name: "no match",
			layerFiles: map[string]LayerInfo{
				"sha256:abc123": {TempPath: filepath.Join(tempDir, "f1"), MediaType: ggufLayerMediaType},
			},
			patterns: []string{"application/json"},
			expected: 0,
		},
		{
			name: "multiple patterns match multiple files",
			layerFiles: map[string]LayerInfo{
				"sha256:abc123": {TempPath: filepath.Join(tempDir, "f1"), MediaType: ggufLayerMediaType},
				"sha256:def456": {TempPath: filepath.Join(tempDir, "f2"), MediaType: "application/octet-stream"},
			},
			patterns: []string{ggufLayerMediaType, "application/octet-stream"},
			expected: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := NewContainerImageModel(tempDir, test.layerFiles)

			locations, err := resolver.FilesByMediaType(test.patterns...)
			require.NoError(t, err)
			assert.Len(t, locations, test.expected)
		})
	}
}

func TestOCIModelResolver_FileContentsByLocation(t *testing.T) {
	tempDir := t.TempDir()
	content := []byte("test gguf content")

	tempFile := filepath.Join(tempDir, "test.gguf")
	require.NoError(t, os.WriteFile(tempFile, content, 0600))

	digest := "sha256:abc123"
	layerFiles := map[string]LayerInfo{
		digest: {TempPath: tempFile, MediaType: ggufLayerMediaType},
	}

	resolver := NewContainerImageModel(tempDir, layerFiles)

	tests := []struct {
		name      string
		digest    string
		wantErr   bool
		wantData  []byte
		errSubstr string
	}{
		{
			name:     "valid location returns content",
			digest:   digest,
			wantErr:  false,
			wantData: content,
		},
		{
			name:      "invalid digest returns error",
			digest:    "sha256:invalid",
			wantErr:   true,
			errSubstr: "no file found for digest",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loc := file.NewVirtualLocationFromCoordinates(
				file.NewCoordinates("/", test.digest),
				"/",
			)

			reader, err := resolver.FileContentsByLocation(loc)

			if test.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.errSubstr)
				return
			}

			require.NoError(t, err)
			defer reader.Close()

			data, err := io.ReadAll(reader)
			require.NoError(t, err)
			assert.Equal(t, test.wantData, data)
		})
	}
}
