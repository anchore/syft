package ai

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestNewGGUFPackage(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *pkg.GGUFFileHeader
		locations []file.Location
		checkFunc func(t *testing.T, p pkg.Package)
	}{
		{
			name: "complete GGUF package with all fields",
			metadata: &pkg.GGUFFileHeader{
				ModelName:       "llama3-8b-instruct",
				ModelVersion:    "3.0",
				License:         "Apache-2.0",
				Architecture:    "llama",
				Quantization:    "Q4_K_M",
				Parameters:      8030000000,
				GGUFVersion: 3,
				TensorCount: 291,
				Header:      map[string]any{},
			},
			locations: []file.Location{file.NewLocation("/models/llama3-8b.gguf")},
			checkFunc: func(t *testing.T, p pkg.Package) {
				if d := cmp.Diff("llama3-8b-instruct", p.Name); d != "" {
					t.Errorf("Name mismatch (-want +got):\n%s", d)
				}
				if d := cmp.Diff("3.0", p.Version); d != "" {
					t.Errorf("Version mismatch (-want +got):\n%s", d)
				}
				if d := cmp.Diff(pkg.ModelPkg, p.Type); d != "" {
					t.Errorf("Type mismatch (-want +got):\n%s", d)
				}
				assert.Empty(t, p.PURL, "PURL should not be set for model packages")
				assert.Len(t, p.Licenses.ToSlice(), 1)
				if d := cmp.Diff("Apache-2.0", p.Licenses.ToSlice()[0].Value); d != "" {
					t.Errorf("License value mismatch (-want +got):\n%s", d)
				}
				assert.NotEmpty(t, p.ID())
			},
		},
		{
			name: "minimal GGUF package",
			metadata: &pkg.GGUFFileHeader{
				ModelName:    "simple-model",
				ModelVersion: "1.0",
				Architecture: "gpt2",
				GGUFVersion:  3,
				TensorCount:  50,
			},
			locations: []file.Location{file.NewLocation("/models/simple.gguf")},
			checkFunc: func(t *testing.T, p pkg.Package) {
				if d := cmp.Diff("simple-model", p.Name); d != "" {
					t.Errorf("Name mismatch (-want +got):\n%s", d)
				}
				if d := cmp.Diff("1.0", p.Version); d != "" {
					t.Errorf("Version mismatch (-want +got):\n%s", d)
				}
				if d := cmp.Diff(pkg.ModelPkg, p.Type); d != "" {
					t.Errorf("Type mismatch (-want +got):\n%s", d)
				}
				assert.Empty(t, p.PURL, "PURL should not be set for model packages")
				assert.Empty(t, p.Licenses.ToSlice())
			},
		},
		{
			name: "GGUF package with multiple locations",
			metadata: &pkg.GGUFFileHeader{
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

			if d := cmp.Diff(tt.metadata.ModelName, p.Name); d != "" {
				t.Errorf("Name mismatch (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tt.metadata.ModelVersion, p.Version); d != "" {
				t.Errorf("Version mismatch (-want +got):\n%s", d)
			}
			if d := cmp.Diff(pkg.ModelPkg, p.Type); d != "" {
				t.Errorf("Type mismatch (-want +got):\n%s", d)
			}

			// Verify metadata is attached
			metadata, ok := p.Metadata.(pkg.GGUFFileHeader)
			require.True(t, ok, "metadata should be GGUFFileHeader")
			if d := cmp.Diff(*tt.metadata, metadata); d != "" {
				t.Errorf("Metadata mismatch (-want +got):\n%s", d)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, p)
			}
		})
	}
}
