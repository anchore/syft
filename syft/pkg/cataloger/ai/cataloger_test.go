package ai

import (
	"os"
	"path/filepath"
	"testing"

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

func TestGGUFCataloger(t *testing.T) {
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
					withStringKV("general.some_random_kv", "foobar").
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
						Architecture:          "llama",
						Quantization:          "Unknown",
						Parameters:            0,
						GGUFVersion:           3,
						TensorCount:           0,
						MetadataKeyValuesHash: "6e3d368066455ce4",
						Header: map[string]interface{}{
							"general.some_random_kv": "foobar",
						},
					},
				},
			},
			expectedRelationships: nil,
		},
		{
			name: "catalog GGUF file with minimal metadata",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				data := newTestGGUFBuilder().
					withVersion(3).
					withStringKV("general.architecture", "gpt2").
					withStringKV("general.name", "gpt2-small").
					withStringKV("gpt2.context_length", "1024").
					withUint32KV("gpt2.embedding_length", 768).
					build()

				path := filepath.Join(dir, "gpt2-small.gguf")
				os.WriteFile(path, data, 0644)
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "gpt2-small",
					Version: "",
					Type:    pkg.ModelPkg,
					Licenses: pkg.NewLicenseSet(),
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "gpt2",
						Quantization:          "Unknown",
						Parameters:            0,
						GGUFVersion:           3,
						TensorCount:           0,
						MetadataKeyValuesHash: "9dc6f23591062a27",
						Header: map[string]interface{}{
							"gpt2.context_length":   "1024",
							"gpt2.embedding_length": uint32(768),
						},
					},
				},
			},
			expectedRelationships: nil,
		},
		{
			name: "catalog multiple GGUF files",
			setup: func(t *testing.T) string {
				dir := t.TempDir()

				// First model - Llama with custom training data
				data1 := newTestGGUFBuilder().
					withVersion(3).
					withStringKV("general.architecture", "llama").
					withStringKV("general.name", "model-1").
					withStringKV("general.version", "1.0").
					withStringKV("llama.attention.head_count", "32").
					withUint32KV("llama.attention.layer_norm_rms_epsilon", 999).
					build()
				os.WriteFile(filepath.Join(dir, "model-1.gguf"), data1, 0644)

				// Second model - GPT2 with different config
				data2 := newTestGGUFBuilder().
					withVersion(3).
					withStringKV("general.architecture", "gpt2").
					withStringKV("general.name", "model-2").
					withStringKV("general.version", "2.0").
					withStringKV("general.license", "MIT").
					withStringKV("gpt2.block_count", "12").
					withUint64KV("tokenizer.ggml.bos_token_id", 50256).
					build()
				os.WriteFile(filepath.Join(dir, "model-2.gguf"), data2, 0644)

				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "model-1",
					Version: "1.0",
					Type:    pkg.ModelPkg,
					Licenses: pkg.NewLicenseSet(),
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "llama",
						Quantization:          "Unknown",
						Parameters:            0,
						GGUFVersion:           3,
						TensorCount:           0,
						MetadataKeyValuesHash: "57e0dbea7d2efa6e",
						Header: map[string]interface{}{
							"llama.attention.head_count":              "32",
							"llama.attention.layer_norm_rms_epsilon": uint32(999),
						},
					},
				},
				{
					Name:    "model-2",
					Version: "2.0",
					Type:    pkg.ModelPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromFields("MIT", "", nil),
					),
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "gpt2",
						Quantization:          "Unknown",
						Parameters:            0,
						GGUFVersion:           3,
						TensorCount:           0,
						MetadataKeyValuesHash: "f85de1bf9be304bb",
						Header: map[string]interface{}{
							"gpt2.block_count":            "12",
							"tokenizer.ggml.bos_token_id": uint64(50256),
						},
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
			pkgtest.NewCatalogTester().
				FromDirectory(t, fixtureDir).
				Expects(tt.expectedPackages, tt.expectedRelationships).
				IgnoreLocationLayer().
				IgnorePackageFields("FoundBy", "Locations").
				TestCataloger(t, NewGGUFCataloger())
		})
	}
}
