package golang

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_Mod_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain go.mod files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/go.mod",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				IgnoreUnfulfilledPathResponses("src/go.sum").
				TestCataloger(t, NewGoModFileCataloger(GoCatalogerOpts{}))
		})
	}
}

func Test_Binary_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain binary files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"partial-binary",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewGoModuleBinaryCataloger(GoCatalogerOpts{}))
		})
	}
}

func Test_Binary_Cataloger_Stdlib_Cpe(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		want      string
	}{
		{
			name:      "generateStdlibCpe generates a cpe with a - for a major version",
			candidate: "go1.21.0",
			want:      "cpe:2.3:a:golang:go:1.21.0:-:*:*:*:*:*:*",
		},
		{
			name:      "generateStdlibCpe generates a cpe with an rc candidate for a major rc version",
			candidate: "go1.21rc2",
			want:      "cpe:2.3:a:golang:go:1.21:rc2:*:*:*:*:*:*",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := generateStdlibCpe(tc.candidate)
			assert.NoError(t, err, "expected no err; got %v", err)
			assert.Equal(t, cpe.String(got), tc.want)
		})
	}
}
