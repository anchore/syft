package ai

import (
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
