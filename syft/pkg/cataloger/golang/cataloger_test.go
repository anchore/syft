package golang

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_PackageCataloger_Binary(t *testing.T) {

	tests := []struct {
		name         string
		fixture      string
		expectedPkgs []string
		expectedRels []string
		// wantErr is set where the fixture is expected to catalog cleanly. Without it the tester discards
		// the cataloger's error, so an unknown newly attached to every file in the image cannot fail this
		// table: packages and relationships still match. The packed fixture is the one that needs it, since
		// the UPX reporting policy decides per file whether a gap is worth an unknown.
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "simple module with dependencies",
			fixture: "image-small",
			expectedPkgs: []string{
				"anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/andybalholm/brotli @ v1.1.1 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me)",
				"github.com/golang/snappy @ v0.0.4 (/run-me)",
				"github.com/klauspost/compress @ v1.17.11 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.6 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.3 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.21 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.12 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me)",
				"stdlib @ go1.23.2 (/run-me)",
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 (/run-me)",
			},
			expectedRels: []string{
				"github.com/andybalholm/brotli @ v1.1.1 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/golang/snappy @ v0.0.4 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/klauspost/compress @ v1.17.11 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.6 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.3 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.21 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.12 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"stdlib @ go1.23.2 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
			},
		},
		{
			name:    "upx compressed binary",
			fixture: "image-small-upx",
			wantErr: require.NoError,
			expectedPkgs: []string{
				"anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/andybalholm/brotli @ v1.1.1 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me)",
				"github.com/golang/snappy @ v0.0.4 (/run-me)",
				"github.com/klauspost/compress @ v1.17.11 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.6 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.3 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.21 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.12 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me)",
				"stdlib @ go1.23.2 (/run-me)",
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 (/run-me)",
			},
			expectedRels: []string{
				"github.com/andybalholm/brotli @ v1.1.1 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/golang/snappy @ v0.0.4 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/klauspost/compress @ v1.17.11 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.6 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.3 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.21 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.12 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
				"stdlib @ go1.23.2 (/run-me) [dependency-of] anchore.io/not/real @ v1.0.0 (/run-me)",
			},
		},
		{
			name: "partially built binary",
			// the difference is the build flags used to build the binary... they will not reference the module directly
			// see the dockerfile for details
			fixture: "image-not-a-module",
			expectedPkgs: []string{
				"command-line-arguments @  (/run-me)", // this is the difference!
				"github.com/andybalholm/brotli @ v1.1.1 (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me)",
				"github.com/golang/snappy @ v0.0.4 (/run-me)",
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 (/run-me)",
				"github.com/klauspost/compress @ v1.17.11 (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.6 (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.3 (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.21 (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.12 (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me)",
				"stdlib @ go1.23.2 (/run-me)",
			},
			expectedRels: []string{
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/andybalholm/brotli @ v1.1.1 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/golang/snappy @ v0.0.4 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/klauspost/compress @ v1.17.11 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/klauspost/pgzip @ v1.2.6 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/nwaples/rardecode @ v1.1.3 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/pierrec/lz4/v4 @ v4.1.21 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/ulikunitz/xz @ v0.5.12 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
				"stdlib @ go1.23.2 (/run-me) [dependency-of] command-line-arguments @  (/run-me)",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tester := pkgtest.NewCatalogTester().
				WithImageResolver(t, test.fixture).
				ExpectsPackageStrings(test.expectedPkgs).
				ExpectsRelationshipStrings(test.expectedRels)
			if test.wantErr != nil {
				tester = tester.WithErrorAssertion(test.wantErr)
			}
			tester.TestCataloger(t, NewGoModuleBinaryCataloger(DefaultCatalogerConfig()))
		})
	}

}

// Test_PackageCataloger_Binary_SymbolsFromPackedBinary covers what the packed path used to miss: the
// pclntab is compressed along with everything else, so a UPX binary reported its packages with no symbols
// at all until the unpacked contents were threaded through the rest of the scan instead of only the
// build info read.
func Test_PackageCataloger_Binary_SymbolsFromPackedBinary(t *testing.T) {
	cfg := DefaultCatalogerConfig()
	cfg.CaptureSymbols = cataloging.SymbolScopeAll

	symbolCounts := func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) map[string]int {
		t.Helper()
		counts := make(map[string]int)
		for _, p := range pkgs {
			meta, ok := p.Metadata.(pkg.GolangBinaryBuildinfoEntry)
			require.True(t, ok, "unexpected metadata on %s", p.Name)
			for _, names := range meta.Symbols {
				counts[p.Name] += len(names)
			}
		}
		return counts
	}

	var packed, unpacked map[string]int
	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-small").
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, rels []artifact.Relationship) {
			unpacked = symbolCounts(t, pkgs, rels)
		}).
		TestCataloger(t, NewGoModuleBinaryCataloger(cfg))

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-small-upx").
		// a real `upx --best --lzma` binary must unpack without leaving a gap behind. The reconstruction is
		// truncated to the contiguous extent rebuilt, and a chain that stops short of p_filesize is now a
		// reported partial, so this is the assertion that catches that firing on well-formed output.
		WithErrorAssertion(require.NoError).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, rels []artifact.Relationship) {
			packed = symbolCounts(t, pkgs, rels)
		}).
		TestCataloger(t, NewGoModuleBinaryCataloger(cfg))

	require.NotEmpty(t, unpacked, "the unpacked fixture is the control: it must carry symbols")
	assert.Equal(t, unpacked, packed, "the packed binary must report the same symbols as the one it was packed from")
}

func Test_Mod_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain go.mod files",
			fixture: "testdata/glob-paths",
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
			fixture: "testdata/glob-paths",
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
