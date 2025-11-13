package ai

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestGGUFCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain gguf files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"models/model.gguf",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewGGUFCataloger())
		})
	}
}

func TestGGUFCataloger_Integration(t *testing.T) {
	tests := []struct {
		name                  string
		setup                 func(t *testing.T) string
		expectedPackages      []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name: "catalog single GGUF file",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				data := newTestGGUFBuilder().
					withVersion(3).
					withStringKV("general.architecture", "llama").
					withStringKV("general.name", "llama3-8b").
					withStringKV("general.version", "3.0").
					withStringKV("general.license", "Apache-2.0").
					withStringKV("general.quantization", "Q4_K_M").
					withUint64KV("general.parameter_count", 8030000000).
					build()

				path := filepath.Join(dir, "llama3-8b.gguf")
				os.WriteFile(path, data, 0644)
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "llama3-8b",
					Version: "3.0",
					Type:    pkg.ModelPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromFields("Apache-2.0", "", nil),
					),
					Metadata: pkg.GGUFFileHeader{
						ModelName:    "llama3-8b",
						ModelVersion: "3.0",
						License:      "Apache-2.0",
						Architecture: "llama",
						Quantization: "Unknown",
						Parameters:   0,
						GGUFVersion:  3,
						TensorCount:  0,
						Header:       map[string]interface{}{},
					},
				},
			},
			expectedRelationships: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureDir := tt.setup(t)

			// Use pkgtest to catalog and compare
			tester := pkgtest.NewCatalogTester().
				FromDirectory(t, fixtureDir).
				Expects(tt.expectedPackages, tt.expectedRelationships).
				IgnoreLocationLayer().
				IgnorePackageFields("FoundBy", "Locations"). // These are set by the cataloger
				WithCompareOptions(
					// Ignore MetadataHash as it's computed dynamically
					cmpopts.IgnoreFields(pkg.GGUFFileHeader{}, "MetadataHash"),
				)

			tester.TestCataloger(t, NewGGUFCataloger())
		})
	}
}

func TestGGUFCataloger_Name(t *testing.T) {
	cataloger := NewGGUFCataloger()
	assert.Equal(t, "gguf-cataloger", cataloger.Name())
}
