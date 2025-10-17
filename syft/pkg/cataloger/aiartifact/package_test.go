package aiartifact

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestNewGGUFPackage(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *pkg.GGUFFileMetadata
		locations []file.Location
		checkFunc func(t *testing.T, p pkg.Package)
	}{
		{
			name: "complete GGUF package with all fields",
			metadata: &pkg.GGUFFileMetadata{
				ModelFormat:     "gguf",
				ModelName:       "llama3-8b-instruct",
				ModelVersion:    "3.0",
				License:         "Apache-2.0",
				Architecture:    "llama",
				Quantization:    "Q4_K_M",
				Parameters:      8030000000,
				GGUFVersion:     3,
				TensorCount:     291,
				Header:          map[string]any{},
				TruncatedHeader: false,
			},
			locations: []file.Location{file.NewLocation("/models/llama3-8b.gguf")},
			checkFunc: func(t *testing.T, p pkg.Package) {
				assert.Equal(t, "llama3-8b-instruct", p.Name)
				assert.Equal(t, "3.0", p.Version)
				assert.Equal(t, pkg.ModelPkg, p.Type)
				assert.Empty(t, p.PURL, "PURL should not be set for model packages")
				assert.Len(t, p.Licenses.ToSlice(), 1)
				assert.Equal(t, "Apache-2.0", p.Licenses.ToSlice()[0].Value)
				assert.NotEmpty(t, p.ID())
			},
		},
		{
			name: "minimal GGUF package",
			metadata: &pkg.GGUFFileMetadata{
				ModelFormat:  "gguf",
				ModelName:    "simple-model",
				ModelVersion: "1.0",
				Architecture: "gpt2",
				GGUFVersion:  3,
				TensorCount:  50,
			},
			locations: []file.Location{file.NewLocation("/models/simple.gguf")},
			checkFunc: func(t *testing.T, p pkg.Package) {
				assert.Equal(t, "simple-model", p.Name)
				assert.Equal(t, "1.0", p.Version)
				assert.Equal(t, pkg.ModelPkg, p.Type)
				assert.Empty(t, p.PURL, "PURL should not be set for model packages")
				assert.Empty(t, p.Licenses.ToSlice())
			},
		},
		{
			name: "GGUF package with multiple locations",
			metadata: &pkg.GGUFFileMetadata{
				ModelFormat:  "gguf",
				ModelName:    "multi-location-model",
				ModelVersion: "1.5",
				Architecture: "llama",
				GGUFVersion:  3,
				TensorCount:  150,
			},
			locations: []file.Location{
				file.NewLocation("/models/model1.gguf"),
				file.NewLocation("/models/model2.gguf"),
			},
			checkFunc: func(t *testing.T, p pkg.Package) {
				assert.Len(t, p.Locations.ToSlice(), 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newGGUFPackage(tt.metadata, tt.locations...)

			assert.Equal(t, tt.metadata.ModelName, p.Name)
			assert.Equal(t, tt.metadata.ModelVersion, p.Version)
			assert.Equal(t, pkg.ModelPkg, p.Type)

			// Verify metadata is attached
			metadata, ok := p.Metadata.(pkg.GGUFFileMetadata)
			require.True(t, ok, "metadata should be GGUFFileMetadata")
			assert.Equal(t, *tt.metadata, metadata)

			if tt.checkFunc != nil {
				tt.checkFunc(t, p)
			}
		})
	}
}
