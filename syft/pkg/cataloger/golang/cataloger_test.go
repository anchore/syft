package golang

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PackageCataloger_Binary(t *testing.T) {

	tests := []struct {
		name         string
		fixture      string
		expectedPkgs []string
		expectedRels []string
	}{
		{
			name:    "simple module with dependencies",
			fixture: "image-small",
			expectedPkgs: []string{
				"anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/andybalholm/brotli @ v1.0.1 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me)",
				"github.com/golang/snappy @ v0.0.2 (/run-me)",
				"github.com/klauspost/compress @ v1.11.4 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.5 (/run-me)",
				"github.com/mholt/archiver/v3 @ v3.5.1 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.0 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.2 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.9 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me)",
				"stdlib @ go1.22.4 (/run-me)",
			},
			expectedRels: []string{
				"github.com/andybalholm/brotli @ v1.0.1 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/golang/snappy @ v0.0.2 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/klauspost/compress @ v1.11.4 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.5 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/mholt/archiver/v3 @ v3.5.1 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.0 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.2 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.9 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"stdlib @ go1.22.4 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
			},
		},
		{
			name: "partially built binary",
			// the difference is the build flags used to build the binary... they will not reference the module directly
			// see the dockerfile for details
			fixture: "image-not-a-module",
			expectedPkgs: []string{
				"command-line-arguments @ (devel) (/run-me)", // this is the difference!
				"github.com/andybalholm/brotli @ v1.0.1 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me)",
				"github.com/golang/snappy @ v0.0.2 (/run-me)",
				"github.com/klauspost/compress @ v1.11.4 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.5 (/run-me)",
				"github.com/mholt/archiver/v3 @ v3.5.1 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.0 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.2 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.9 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me)",
				"stdlib @ go1.22.4 (/run-me)",
			},
			expectedRels: []string{
				"github.com/andybalholm/brotli @ v1.0.1 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/golang/snappy @ v0.0.2 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/klauspost/compress @ v1.11.4 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.5 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/mholt/archiver/v3 @ v3.5.1 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.0 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.2 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.9 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
				"stdlib @ go1.22.4 (/run-me) [dependency-of] command-line-arguments @ (devel) (/run-me)",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithImageResolver(t, test.fixture).
				ExpectsPackageStrings(test.expectedPkgs).
				ExpectsRelationshipStrings(test.expectedRels).
				TestCataloger(t, NewGoModuleBinaryCataloger(DefaultCatalogerConfig()))
		})
	}

}

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
				TestCataloger(t, NewGoModuleFileCataloger(CatalogerConfig{}))
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
				TestCataloger(t, NewGoModuleBinaryCataloger(CatalogerConfig{}))
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
			assert.Equal(t, got.Attributes.String(), tc.want)
		})
	}
}
