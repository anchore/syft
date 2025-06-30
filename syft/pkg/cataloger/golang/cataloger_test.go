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

func Test_Source_Cataloger_EntryPoint_Detection(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		expectedPkgs []string
		expectedRels []string
	}{
		{
			name:    "Go source cataloger should detect the topmost gomod and use its search path",
			fixture: "test-fixtures/go-source",
			expectedPkgs: []string{
				"anchore.io/not/real @  ()",
				"github.com/fsnotify/fsnotify @ v1.8.0 ()",
				"github.com/go-viper/mapstructure/v2 @ v2.2.1 ()",
				"github.com/google/uuid @ v1.6.0 ()",
				"github.com/pelletier/go-toml/v2 @ v2.2.3 ()",
				"github.com/sagikazarmark/locafero @ v0.7.0 ()",
				"github.com/sirupsen/logrus @ v1.9.3 ()",
				"github.com/sourcegraph/conc @ v0.3.0 ()",
				"github.com/spf13/afero @ v1.12.0 ()",
				"github.com/spf13/cast @ v1.7.1 ()",
				"github.com/spf13/pflag @ v1.0.6 ()",
				"github.com/spf13/viper @ v1.20.1 ()",
				"github.com/subosito/gotenv @ v1.6.0 ()",
				"go.uber.org/multierr @ v1.10.0 ()",
				"go.uber.org/zap @ v1.27.0 ()",
				"golang.org/x/sys @ v0.33.0 ()",
				"golang.org/x/text @ v0.21.0 ()",
				"gopkg.in/yaml.v3 @ v3.0.1 ()",
			},
			expectedRels: []string{
				"github.com/fsnotify/fsnotify @ v1.8.0 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/go-viper/mapstructure/v2 @ v2.2.1 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/google/uuid @ v1.6.0 () [dependency-of] anchore.io/not/real @  ()",
				"github.com/pelletier/go-toml/v2 @ v2.2.3 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/sagikazarmark/locafero @ v0.7.0 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/sirupsen/logrus @ v1.9.3 () [dependency-of] anchore.io/not/real @  ()",
				"github.com/sourcegraph/conc @ v0.3.0 () [dependency-of] github.com/sagikazarmark/locafero @ v0.7.0 ()",
				"github.com/spf13/afero @ v1.12.0 () [dependency-of] github.com/sagikazarmark/locafero @ v0.7.0 ()",
				"github.com/spf13/afero @ v1.12.0 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/spf13/cast @ v1.7.1 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/spf13/pflag @ v1.0.6 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"github.com/spf13/viper @ v1.20.1 () [dependency-of] anchore.io/not/real @  ()",
				"github.com/subosito/gotenv @ v1.6.0 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
				"go.uber.org/multierr @ v1.10.0 () [dependency-of] go.uber.org/zap @ v1.27.0 ()",
				"go.uber.org/zap @ v1.27.0 () [dependency-of] anchore.io/not/real @  ()",
				"golang.org/x/sys @ v0.33.0 () [dependency-of] github.com/fsnotify/fsnotify @ v1.8.0 ()",
				"golang.org/x/sys @ v0.33.0 () [dependency-of] github.com/sirupsen/logrus @ v1.9.3 ()",
				"golang.org/x/text @ v0.21.0 () [dependency-of] github.com/spf13/afero @ v1.12.0 ()",
				"golang.org/x/text @ v0.21.0 () [dependency-of] github.com/subosito/gotenv @ v1.6.0 ()",
				"gopkg.in/yaml.v3 @ v3.0.1 () [dependency-of] github.com/spf13/viper @ v1.20.1 ()",
			},
		},
		{
			name:    "go source cataloger returns the same as binary given the same source",
			fixture: "test-fixtures/image-small",
			expectedPkgs: []string{
				"anchore.io/not/real @  ()",
				"github.com/andybalholm/brotli @ v1.1.1 ()",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 ()",
				"github.com/golang/snappy @ v0.0.4 ()",
				"github.com/klauspost/compress @ v1.17.11 ()",
				"github.com/klauspost/pgzip @ v1.2.6 ()",
				"github.com/nwaples/rardecode @ v1.1.3 ()",
				"github.com/pierrec/lz4/v4 @ v4.1.21 ()",
				"github.com/ulikunitz/xz @ v0.5.12 ()",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 ()",
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
			},
			expectedRels: []string{
				"github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 () [dependency-of] anchore.io/not/real @  ()",
				"github.com/andybalholm/brotli @ v1.1.1 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/dsnet/compress @ v0.0.2-0.20210315054119-f66993602bf5 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/golang/snappy @ v0.0.4 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/klauspost/compress @ v1.17.11 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/klauspost/compress @ v1.17.11 () [dependency-of] github.com/klauspost/pgzip @ v1.2.6 ()",
				"github.com/klauspost/pgzip @ v1.2.6 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/nwaples/rardecode @ v1.1.3 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/pierrec/lz4/v4 @ v4.1.21 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/ulikunitz/xz @ v0.5.12 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
				"github.com/xi2/xz @ v0.0.0-20171230120015-48954b6210f8 () [dependency-of] github.com/anchore/archiver/v3 @ v3.5.3-0.20241210171143-5b1d8d1c7c51 ()",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsPackageStrings(test.expectedPkgs).
				ExpectsRelationshipStrings(test.expectedRels).
				TestCataloger(t, NewGoSourceCataloger(CatalogerConfig{}))
		})
	}
}
