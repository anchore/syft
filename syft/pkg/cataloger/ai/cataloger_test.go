package ai

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestGGUFCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) string // returns fixture directory
		expected []string
	}{
		{
			name: "finds GGUF files in root",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				createTestGGUFInDir(t, dir, "model1.gguf")
				createTestGGUFInDir(t, dir, "model2.gguf")
				return dir
			},
			expected: []string{
				"model1.gguf",
				"model2.gguf",
			},
		},
		{
			name: "finds GGUF files in subdirectories",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				modelsDir := filepath.Join(dir, "models")
				os.MkdirAll(modelsDir, 0755)
				createTestGGUFInDir(t, modelsDir, "llama.gguf")

				deepDir := filepath.Join(dir, "deep", "nested", "path")
				os.MkdirAll(deepDir, 0755)
				createTestGGUFInDir(t, deepDir, "mistral.gguf")

				return dir
			},
			expected: []string{
				"models/llama.gguf",
				"deep/nested/path/mistral.gguf",
			},
		},
		{
			name: "ignores non-GGUF files",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				createTestGGUFInDir(t, dir, "model.gguf")

				// Create non-GGUF files
				os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("readme"), 0644)
				os.WriteFile(filepath.Join(dir, "model.bin"), []byte("binary"), 0644)
				os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)

				return dir
			},
			expected: []string{
				"model.gguf",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureDir := tt.setup(t)

			pkgtest.NewCatalogTester().
				FromDirectory(t, fixtureDir).
				ExpectsResolverContentQueries(tt.expected).
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
					withTensorCount(291).
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
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "llama3-8b",
						ModelVersion:    "3.0",
						License:         "Apache-2.0",
						Architecture:    "llama",
						Quantization:    "Q4_K_M",
						Parameters:      8030000000,
						GGUFVersion:     3,
						TensorCount:     291,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
			},
			expectedRelationships: nil,
		},
		{
			name: "catalog multiple GGUF files",
			setup: func(t *testing.T) string {
				dir := t.TempDir()

				// Create first model
				data1 := newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(100).
					withStringKV("general.architecture", "llama").
					withStringKV("general.name", "model1").
					withStringKV("general.version", "1.0").
					build()
				os.WriteFile(filepath.Join(dir, "model1.gguf"), data1, 0644)

				// Create second model
				data2 := newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(200).
					withStringKV("general.architecture", "mistral").
					withStringKV("general.name", "model2").
					withStringKV("general.version", "2.0").
					build()
				os.WriteFile(filepath.Join(dir, "model2.gguf"), data2, 0644)

				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "model1",
					Version: "1.0",
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "model1",
						ModelVersion:    "1.0",
						Architecture:    "llama",
						Quantization:    unknownGGUFData,
						GGUFVersion:     3,
						TensorCount:     100,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
				{
					Name:    "model2",
					Version: "2.0",
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "model2",
						ModelVersion:    "2.0",
						Architecture:    "mistral",
						Quantization:    unknownGGUFData,
						GGUFVersion:     3,
						TensorCount:     200,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
			},
			expectedRelationships: nil,
		},
		{
			name: "catalog GGUF in nested directories",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				nestedDir := filepath.Join(dir, "models", "quantized")
				os.MkdirAll(nestedDir, 0755)

				data := newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(150).
					withStringKV("general.architecture", "qwen").
					withStringKV("general.name", "qwen-nested").
					build()

				os.WriteFile(filepath.Join(nestedDir, "qwen.gguf"), data, 0644)
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "qwen-nested",
					Version: unknownGGUFData,
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "qwen-nested",
						ModelVersion:    unknownGGUFData,
						Architecture:    "qwen",
						Quantization:    unknownGGUFData,
						GGUFVersion:     3,
						TensorCount:     150,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
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
					// Ignore Hash as it's computed dynamically
					cmpopts.IgnoreFields(pkg.GGUFFileMetadata{}, "Hash"),
				)

			tester.TestCataloger(t, NewGGUFCataloger())
		})
	}
}

func TestGGUFCataloger_SkipsInvalidFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a valid GGUF
	validData := newTestGGUFBuilder().
		withVersion(3).
		withTensorCount(100).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "valid-model").
		build()
	os.WriteFile(filepath.Join(dir, "valid.gguf"), validData, 0644)

	// Create an invalid GGUF (wrong magic)
	invalidData := newTestGGUFBuilder().buildInvalidMagic()
	os.WriteFile(filepath.Join(dir, "invalid.gguf"), invalidData, 0644)

	// Create a truncated GGUF
	os.WriteFile(filepath.Join(dir, "truncated.gguf"), []byte{0x47}, 0644)

	// Catalog should succeed and only return the valid package
	tester := pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			// Should only find the valid model
			require.Len(t, pkgs, 1)
			assert.Equal(t, "valid-model", pkgs[0].Name)
		})

	tester.TestCataloger(t, NewGGUFCataloger())
}

func TestGGUFCataloger_Name(t *testing.T) {
	cataloger := NewGGUFCataloger()
	assert.Equal(t, "gguf-cataloger", cataloger.Name())
}

func TestGGUFCataloger_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory to ensure glob still runs
	os.MkdirAll(filepath.Join(dir, "models"), 0755)

	tester := pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, rels []artifact.Relationship) {
			assert.Empty(t, pkgs)
			assert.Empty(t, rels)
		})

	tester.TestCataloger(t, NewGGUFCataloger())
}

func TestGGUFCataloger_MixedFiles(t *testing.T) {
	dir := t.TempDir()

	// Create GGUF file
	ggufData := newTestGGUFBuilder().
		withVersion(3).
		withTensorCount(100).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "test-model").
		build()
	os.WriteFile(filepath.Join(dir, "model.gguf"), ggufData, 0644)

	// Create other file types
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Models"), 0644)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(dir, "weights.bin"), []byte("weights"), 0644)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)

	tester := pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			// Should only find the GGUF model
			require.Len(t, pkgs, 1)
			assert.Equal(t, "test-model", pkgs[0].Name)
			assert.Equal(t, pkg.ModelPkg, pkgs[0].Type)
		})

	tester.TestCataloger(t, NewGGUFCataloger())
}

func TestGGUFCataloger_CaseInsensitiveGlob(t *testing.T) {
	// Test that the glob pattern is case-sensitive (as expected for **/*.gguf)
	dir := t.TempDir()

	// Create lowercase .gguf
	data := newTestGGUFBuilder().
		withVersion(3).
		withTensorCount(100).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "lowercase").
		build()
	os.WriteFile(filepath.Join(dir, "model.gguf"), data, 0644)

	// Create uppercase .GGUF (should not match the glob)
	os.WriteFile(filepath.Join(dir, "MODEL.GGUF"), data, 0644)

	tester := pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			// Depending on filesystem case-sensitivity, we may get 1 or 2 packages
			// On case-insensitive filesystems (macOS), both might match
			// On case-sensitive filesystems (Linux), only lowercase matches
			assert.GreaterOrEqual(t, len(pkgs), 1, "should find at least the lowercase file")
		})

	tester.TestCataloger(t, NewGGUFCataloger())
}

// createTestGGUFInDir creates a minimal test GGUF file in the specified directory
func createTestGGUFInDir(t *testing.T, dir, filename string) {
	t.Helper()
	data := newTestGGUFBuilder().
		withVersion(3).
		withTensorCount(100).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "test-model").
		build()

	path := filepath.Join(dir, filename)
	err := os.WriteFile(path, data, 0644)
	require.NoError(t, err)
}
