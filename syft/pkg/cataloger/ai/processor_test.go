package ai

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

func Test_ggufMergeProcessor(t *testing.T) {
	tests := []struct {
		name              string
		pkgs              []pkg.Package
		wantPkgCount      int
		wantFilePartCount int
	}{
		{
			name: "single named package merges nameless headers",
			pkgs: []pkg.Package{
				{Name: "model", Metadata: pkg.GGUFFileHeader{MetadataKeyValuesHash: "abc"}},
				{Name: "", Metadata: pkg.GGUFFileHeader{MetadataKeyValuesHash: "part1"}},
				{Name: "", Metadata: pkg.GGUFFileHeader{MetadataKeyValuesHash: "part2"}},
			},
			wantPkgCount:      1,
			wantFilePartCount: 2,
		},
		{
			name: "multiple named packages returns all without merging",
			pkgs: []pkg.Package{
				{Name: "model1", Metadata: pkg.GGUFFileHeader{}},
				{Name: "model2", Metadata: pkg.GGUFFileHeader{}},
				{Name: "", Metadata: pkg.GGUFFileHeader{}},
			},
			wantPkgCount:      2,
			wantFilePartCount: 0,
		},
		{
			name: "no named packages returns empty result",
			pkgs: []pkg.Package{
				{Name: "", Metadata: pkg.GGUFFileHeader{}},
				{Name: "", Metadata: pkg.GGUFFileHeader{}},
			},
			wantPkgCount:      0,
			wantFilePartCount: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _, err := ggufMergeProcessor(test.pkgs, nil, nil)
			require.NoError(t, err)
			assert.Len(t, got, test.wantPkgCount)

			if test.wantPkgCount == 1 && test.wantFilePartCount > 0 {
				header, ok := got[0].Metadata.(pkg.GGUFFileHeader)
				require.True(t, ok)
				assert.Len(t, header.Parts, test.wantFilePartCount)
			}
		})
	}
}

func Test_ggufMergeProcessor_mergesDespiteError(t *testing.T) {
	// one layer failing to parse must not drop the rest of the model
	parseErr := errors.New("one layer failed to parse")
	pkgs := []pkg.Package{
		{Name: "model", Metadata: pkg.GGUFFileHeader{MetadataKeyValuesHash: "abc"}},
		{Name: "", Metadata: pkg.GGUFFileHeader{MetadataKeyValuesHash: "part1"}},
	}

	got, _, err := ggufMergeProcessor(pkgs, nil, parseErr)
	require.ErrorIs(t, err, parseErr)
	require.Len(t, got, 1)
	assert.Equal(t, "model", got[0].Name)
	header, ok := got[0].Metadata.(pkg.GGUFFileHeader)
	require.True(t, ok)
	assert.Len(t, header.Parts, 1)
}
