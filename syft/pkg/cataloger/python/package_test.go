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
		metadata *pkg.PythonPackageMetadata
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
			metadata: &pkg.PythonPackageMetadata{
				Name:    "bogus",  // note: ignored
				Version: "v0.2.0", // note: ignored
				DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
					VCS:      "git",
					URL:      "https://github.com/test/test.git",
					CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
			want: "pkg:pypi/name@v0.1.0?vcs_url=git+https://github.com/test/test.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.name, tt.version, tt.metadata))
		})
	}
}
