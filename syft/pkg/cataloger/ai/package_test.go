package ai

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestNewGGUFPackage(t *testing.T) {
	tests := []struct {
		name     string
		metadata *pkg.GGUFFileHeader
		input    struct {
			modelName string
			version   string
			license   string
			locations []file.Location
		}
		expected pkg.Package
	}{
		{
			name: "complete GGUF package with all fields",
			input: struct {
				modelName string
				version   string
				license   string
				locations []file.Location
			}{
				modelName: "llama3-8b",
				version:   "3.0",
				license:   "Apache-2.0",
				locations: []file.Location{file.NewLocation("/models/llama3-8b.gguf")},
			},
			metadata: &pkg.GGUFFileHeader{
				Architecture: "llama",
				Quantization: "Q4_K_M",
				Parameters:   8030000000,
				GGUFVersion:  3,
				TensorCount:  291,
				RemainingKeyValues: map[string]any{
					"general.random_kv": "foobar",
				},
			},
			expected: pkg.Package{
				Name:    "llama3-8b",
				Version: "3.0",
				Type:    pkg.ModelPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromFields("Apache-2.0", "", nil),
				),
				Metadata: pkg.GGUFFileHeader{
					Architecture: "llama",
					Quantization: "Q4_K_M",
					Parameters:   8030000000,
					GGUFVersion:  3,
					TensorCount:  291,
					RemainingKeyValues: map[string]any{
						"general.random_kv": "foobar",
					},
				},
				Locations: file.NewLocationSet(file.NewLocation("/models/llama3-8b.gguf")),
			},
		},
		{
			name: "minimal GGUF package",
			input: struct {
				modelName string
				version   string
				license   string
				locations []file.Location
			}{
				modelName: "gpt2-small",
				version:   "1.0",
				license:   "MIT",
				locations: []file.Location{file.NewLocation("/models/simple.gguf")},
			},
			metadata: &pkg.GGUFFileHeader{
				Architecture: "gpt2",
				GGUFVersion:  3,
				TensorCount:  50,
			},
			expected: pkg.Package{
				Name:    "gpt2-small",
				Version: "1.0",
				Type:    pkg.ModelPkg,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromFields("MIT", "", nil),
				),
				Metadata: pkg.GGUFFileHeader{
					Architecture: "gpt2",
					GGUFVersion:  3,
					TensorCount:  50,
				},
				Locations: file.NewLocationSet(file.NewLocation("/models/simple.gguf")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := newGGUFPackage(
				tt.metadata,
				tt.input.modelName,
				tt.input.version,
				tt.input.license,
				tt.input.locations...,
			)

			// Verify metadata type
			_, ok := actual.Metadata.(pkg.GGUFFileHeader)
			require.True(t, ok, "metadata should be GGUFFileHeader")

			// Use AssertPackagesEqual for comprehensive comparison
			pkgtest.AssertPackagesEqual(t, tt.expected, actual)
		})
	}
}
