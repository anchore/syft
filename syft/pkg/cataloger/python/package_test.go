package python

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		testName string
		name     string
		version  string
		metadata *pkg.PythonPackage
		want     string
	}{
		{
			testName: "without metadata",
			name:     "name",
			version:  "v0.1.0",
			want:     "pkg:pypi/name@v0.1.0",
		},
		{
			testName: "with vcs info",
			name:     "name",
			version:  "v0.1.0",
			metadata: &pkg.PythonPackage{
				Name:    "bogus",  // note: ignored
				Version: "v0.2.0", // note: ignored
				DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
					VCS:      "git",
					URL:      "https://github.com/test/test.git",
					CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
			want: "pkg:pypi/name@v0.1.0?vcs_url=git%2Bhttps://github.com/test/test.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.name, tt.version, tt.metadata))
		})
	}
}

func Test_normalization(t *testing.T) {
	normalForm := "friendly-bard"
	tests := []string{
		normalForm,
		"Friendly-Bard",
		"FRIENDLY-BARD",
		"friendly.bard",
		"friendly_bard",
		"friendly--bard",
		"FrIeNdLy-._.-bArD",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			assert.Equal(t, normalForm, normalize(tt))
		})
	}
}
