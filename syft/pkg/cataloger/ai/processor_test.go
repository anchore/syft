package ai

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func Test_ggufMergeProcessor(t *testing.T) {
	tests := []struct {
		name                string
		pkgs                []pkg.Package
		rels                []artifact.Relationship
		err                 error
		wantPkgCount        int
		wantMergedHeaders   int // number of headers merged into the winner
		wantPkgNames        []string
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name:         "single package with name - no change",
			pkgs:         []pkg.Package{pkgWithName("model-a", "llama", "Q4_K_M")},
			wantPkgCount: 1,
			wantPkgNames: []string{"model-a"},
		},
		{
			name:         "single package without name - filtered out",
			pkgs:         []pkg.Package{pkgWithName("", "llama", "Q4_K_M")},
			wantPkgCount: 0,
			wantPkgNames: []string{},
		},
		{
			name: "one named, one nameless - merge headers",
			pkgs: []pkg.Package{
				pkgWithName("model-a", "llama", "Q4_K_M"),
				pkgWithName("", "llama", "Q8_0"),
			},
			wantPkgCount:      1,
			wantMergedHeaders: 1,
			wantPkgNames:      []string{"model-a"},
		},
		{
			name: "one named, multiple nameless - merge all headers",
			pkgs: []pkg.Package{
				pkgWithName("model-a", "llama", "Q4_K_M"),
				pkgWithName("", "llama", "Q8_0"),
				pkgWithName("", "llama", "Q4_0"),
				pkgWithName("", "llama", "Q5_K_S"),
			},
			wantPkgCount:      1,
			wantMergedHeaders: 3,
			wantPkgNames:      []string{"model-a"},
		},
		{
			name: "multiple named packages - no merging",
			pkgs: []pkg.Package{
				pkgWithName("model-a", "llama", "Q4_K_M"),
				pkgWithName("model-b", "qwen", "Q8_0"),
			},
			wantPkgCount:      2,
			wantMergedHeaders: 0,
			wantPkgNames:      []string{"model-a", "model-b"},
		},
		{
			name: "multiple named with nameless - no merging, nameless filtered",
			pkgs: []pkg.Package{
				pkgWithName("model-a", "llama", "Q4_K_M"),
				pkgWithName("model-b", "qwen", "Q8_0"),
				pkgWithName("", "mistral", "Q4_0"),
			},
			wantPkgCount:      2,
			wantMergedHeaders: 0,
			wantPkgNames:      []string{"model-a", "model-b"},
		},
		{
			name:         "empty input",
			pkgs:         []pkg.Package{},
			wantPkgCount: 0,
			wantPkgNames: []string{},
		},
		{
			name: "error is propagated",
			pkgs: []pkg.Package{
				pkgWithName("model-a", "llama", "Q4_K_M"),
			},
			err:          errors.New("upstream error"),
			wantPkgCount: 1,
			wantPkgNames: []string{"model-a"},
			wantErr:      assert.Error,
		},
		{
			name: "relationships are preserved",
			pkgs: []pkg.Package{
				pkgWithName("model-a", "llama", "Q4_K_M"),
			},
			rels: []artifact.Relationship{
				{Type: artifact.ContainsRelationship},
			},
			wantPkgCount: 1,
			wantPkgNames: []string{"model-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			gotPkgs, gotRels, err := ggufMergeProcessor(tt.pkgs, tt.rels, tt.err)

			tt.wantErr(t, err)
			assert.Len(t, gotPkgs, tt.wantPkgCount)

			// Verify package names
			var gotNames []string
			for _, p := range gotPkgs {
				gotNames = append(gotNames, p.Name)
			}
			assert.ElementsMatch(t, tt.wantPkgNames, gotNames)

			// Verify merged headers count (only when single named package)
			if tt.wantMergedHeaders > 0 && len(gotPkgs) == 1 {
				header, ok := gotPkgs[0].Metadata.(*pkg.GGUFFileHeader)
				require.True(t, ok, "expected GGUFFileHeader metadata")
				assert.Len(t, header.GGUFFileHeaders, tt.wantMergedHeaders)
			}

			// Verify relationships preserved
			assert.Len(t, gotRels, len(tt.rels))
		})
	}
}

func Test_ggufMergeProcessor_mergedHeaderContent(t *testing.T) {
	// Test that merged headers contain the correct data
	named := pkgWithName("model-a", "llama", "Q4_K_M")
	nameless1 := pkgWithName("", "llama", "Q8_0")
	nameless2 := pkgWithName("", "qwen", "Q4_0")

	gotPkgs, _, err := ggufMergeProcessor([]pkg.Package{named, nameless1, nameless2}, nil, nil)
	require.NoError(t, err)
	require.Len(t, gotPkgs, 1)

	header, ok := gotPkgs[0].Metadata.(*pkg.GGUFFileHeader)
	require.True(t, ok)

	// Winner should have original metadata
	assert.Equal(t, "llama", header.Architecture)
	assert.Equal(t, "Q4_K_M", header.Quantization)

	// Should have merged headers
	require.Len(t, header.GGUFFileHeaders, 2)

	// Check merged header content
	archs := []string{header.GGUFFileHeaders[0].Architecture, header.GGUFFileHeaders[1].Architecture}
	quants := []string{header.GGUFFileHeaders[0].Quantization, header.GGUFFileHeaders[1].Quantization}

	assert.ElementsMatch(t, []string{"llama", "qwen"}, archs)
	assert.ElementsMatch(t, []string{"Q8_0", "Q4_0"}, quants)
}

// pkgWithName creates a test package with GGUF metadata
func pkgWithName(name, arch, quant string) pkg.Package {
	return pkg.Package{
		Name: name,
		Type: pkg.ModelPkg,
		Metadata: &pkg.GGUFFileHeader{
			Architecture: arch,
			Quantization: quant,
			GGUFVersion:  3,
		},
	}
}

// pkgWithNameAndHash creates a test package with GGUF metadata and a metadata hash
func pkgWithNameAndHash(name, arch, quant, hash string) pkg.Package {
	return pkg.Package{
		Name: name,
		Type: pkg.ModelPkg,
		Metadata: &pkg.GGUFFileHeader{
			Architecture:          arch,
			Quantization:          quant,
			GGUFVersion:           3,
			MetadataKeyValuesHash: hash,
		},
	}
}

// pkgWithVersion creates a test package with specific GGUF version
func pkgWithVersion(name string, version uint32) pkg.Package {
	return pkg.Package{
		Name: name,
		Type: pkg.ModelPkg,
		Metadata: &pkg.GGUFFileHeader{
			GGUFVersion: version,
		},
	}
}

func Test_deduplicateAndFilterHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []pkg.GGUFFileHeader
		want    int // number of headers expected after deduplication
	}{
		{
			name:    "empty input",
			headers: nil,
			want:    0,
		},
		{
			name: "filter out version 0 headers",
			headers: []pkg.GGUFFileHeader{
				{GGUFVersion: 0},
				{GGUFVersion: 0},
				{GGUFVersion: 3, Architecture: "llama"},
			},
			want: 1,
		},
		{
			name: "deduplicate by hash",
			headers: []pkg.GGUFFileHeader{
				{GGUFVersion: 3, Architecture: "llama", MetadataKeyValuesHash: "hash1"},
				{GGUFVersion: 3, Architecture: "llama", MetadataKeyValuesHash: "hash1"},
				{GGUFVersion: 3, Architecture: "qwen", MetadataKeyValuesHash: "hash2"},
			},
			want: 2,
		},
		{
			name: "deduplicate by fields when no hash",
			headers: []pkg.GGUFFileHeader{
				{GGUFVersion: 3, Architecture: "llama", Quantization: "Q4_K_M"},
				{GGUFVersion: 3, Architecture: "llama", Quantization: "Q4_K_M"},
				{GGUFVersion: 3, Architecture: "llama", Quantization: "Q8_0"},
			},
			want: 2,
		},
		{
			name: "mixed: filter empty and deduplicate",
			headers: []pkg.GGUFFileHeader{
				{GGUFVersion: 0},
				{GGUFVersion: 0},
				{GGUFVersion: 3, Architecture: "llama", MetadataKeyValuesHash: "hash1"},
				{GGUFVersion: 3, Architecture: "llama", MetadataKeyValuesHash: "hash1"},
				{GGUFVersion: 3, Architecture: "qwen", MetadataKeyValuesHash: "hash2"},
				{GGUFVersion: 0},
			},
			want: 2,
		},
		{
			name: "all unique headers preserved",
			headers: []pkg.GGUFFileHeader{
				{GGUFVersion: 3, Architecture: "llama", Quantization: "Q4_K_M"},
				{GGUFVersion: 3, Architecture: "llama", Quantization: "Q8_0"},
				{GGUFVersion: 3, Architecture: "qwen", Quantization: "Q4_0"},
			},
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateAndFilterHeaders(tt.headers)
			assert.Len(t, got, tt.want)
		})
	}
}

func Test_ggufMergeProcessor_filtersEmptyHeaders(t *testing.T) {
	// This tests the scenario from the issue: many empty headers (version 0) should be filtered
	named := pkgWithName("model-a", "llama", "Q4_K_M")
	empty1 := pkgWithVersion("", 0)
	empty2 := pkgWithVersion("", 0)
	valid := pkgWithName("", "qwen", "Q8_0")

	gotPkgs, _, err := ggufMergeProcessor([]pkg.Package{named, empty1, empty2, valid}, nil, nil)
	require.NoError(t, err)
	require.Len(t, gotPkgs, 1)

	header, ok := gotPkgs[0].Metadata.(*pkg.GGUFFileHeader)
	require.True(t, ok)

	// Only the valid nameless header should remain (empty ones filtered out)
	assert.Len(t, header.GGUFFileHeaders, 1)
	assert.Equal(t, "qwen", header.GGUFFileHeaders[0].Architecture)
}

func Test_ggufMergeProcessor_deduplicatesByHash(t *testing.T) {
	named := pkgWithNameAndHash("model-a", "llama", "Q4_K_M", "main-hash")
	dup1 := pkgWithNameAndHash("", "llama", "Q8_0", "shared-hash")
	dup2 := pkgWithNameAndHash("", "llama", "Q8_0", "shared-hash")
	unique := pkgWithNameAndHash("", "qwen", "Q4_0", "unique-hash")

	gotPkgs, _, err := ggufMergeProcessor([]pkg.Package{named, dup1, dup2, unique}, nil, nil)
	require.NoError(t, err)
	require.Len(t, gotPkgs, 1)

	header, ok := gotPkgs[0].Metadata.(*pkg.GGUFFileHeader)
	require.True(t, ok)

	// Should have 2 unique headers (duplicates removed)
	assert.Len(t, header.GGUFFileHeaders, 2)
}
