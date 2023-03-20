package golang

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source"
)

func Test_LicenseSearch(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "github.com/someorg/somename",
			version:  "v0.3.2",
			expected: "Apache-2.0",
		},
		{
			name:     "github.com/CapORG/CapProject",
			version:  "v4.111.5",
			expected: "MIT",
		},
	}

	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := path.Join(wd, "test-fixtures", "licenses")
	gopath := os.Getenv("GOPATH")
	err = os.Setenv("GOPATH", dir)
	defer func() { _ = os.Setenv("GOPATH", gopath) }()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := newGoLicenses(true)
			licenses, err := l.getLicenses(source.MockResolver{}, test.name, test.version)
			require.NoError(t, err)

			require.Len(t, licenses, 1)

			require.Equal(t, test.expected, licenses[0])
		})
	}
}

func Test_processCaps(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "CycloneDX",
			expected: "!cyclone!d!x",
		},
		{
			name:     "Azure",
			expected: "!azure",
		},
		{
			name:     "xkcd",
			expected: "xkcd",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := processCaps(test.name)

			require.Equal(t, test.expected, got)
		})
	}
}
