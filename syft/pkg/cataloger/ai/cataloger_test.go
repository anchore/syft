package ai

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/internal/fileresolver"

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
			fixture: "testdata/glob-paths",
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
						RemainingKeyValues: map[string]any{
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
					Name:     "gpt2-small",
					Version:  "",
					Type:     pkg.ModelPkg,
					Licenses: pkg.NewLicenseSet(),
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "gpt2",
						Quantization:          "Unknown",
						Parameters:            0,
						GGUFVersion:           3,
						TensorCount:           0,
						MetadataKeyValuesHash: "9dc6f23591062a27",
						RemainingKeyValues: map[string]any{
							"gpt2.context_length":   "1024",
							"gpt2.embedding_length": uint32(768),
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

func TestGGUFCataloger_ociLayers(t *testing.T) {
	// a GGUF OCI artifact is merged into one named package, while the other
	// application/vnd.docker.ai.* layers (config, model.file, license and
	// safetensors weights) never reach the GGUF parser.
	named := newTestGGUFBuilder().
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "llama3-8b").
		build()
	part := newTestGGUFBuilder().withStringKV("general.architecture", "llama").build()

	dir := t.TempDir()
	layers := map[string]fileresolver.LayerInfo{}
	for digest, l := range map[string]struct {
		mediaType string
		content   []byte
	}{
		"sha256:named":   {dockerAIGGUFMediaType, named},
		"sha256:part":    {dockerAIGGUFMediaType, part},
		"sha256:config":  {dockerAIModelConfigMediaTypes[0], []byte("not a gguf file")},
		"sha256:file":    {dockerAIModelFileMediaType, []byte("not a gguf file")},
		"sha256:license": {dockerAILicenseMediaType, []byte("not a gguf file")},
		"sha256:weights": {dockerAISafeTensorsMediaType, []byte("not a gguf file")},
	} {
		p := filepath.Join(dir, digest[len("sha256:"):])
		require.NoError(t, os.WriteFile(p, l.content, 0o600))
		layers[digest] = fileresolver.LayerInfo{TempPath: p, MediaType: l.mediaType}
	}
	resolver := fileresolver.NewContainerImageModel(dir, layers, "example/model:latest")
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir()))

	pkgs, _, err := NewGGUFCataloger().Catalog(ctx, resolver)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "llama3-8b", pkgs[0].Name)
	header, ok := pkgs[0].Metadata.(pkg.GGUFFileHeader)
	require.True(t, ok)
	assert.Len(t, header.Parts, 1)
}
