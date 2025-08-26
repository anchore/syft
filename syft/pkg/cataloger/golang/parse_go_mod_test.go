package golang

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseGoMod(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/go-mod-fixtures/one-package/go.mod",
			expected: []pkg.Package{
				{
					Name:      "github.com/bmatcuk/doublestar",
					Version:   "v1.3.1",
					PURL:      "pkg:golang/github.com/bmatcuk/doublestar@v1.3.1",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/one-package/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
			},
		},
		{
			fixture: "test-fixtures/go-mod-fixtures/relative-replace/go.mod",
			expected: []pkg.Package{
				{
					Name:      "github.com/aws/aws-sdk-go-v2",
					Version:   "",
					PURL:      "pkg:golang/github.com/aws/aws-sdk-go-v2",
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/relative-replace/go.mod")),
					Metadata:  pkg.GolangModuleEntry{},
				},
			},
		},
		{

			fixture: "test-fixtures/go-mod-fixtures/many-packages/go.mod",
			expected: []pkg.Package{
				{
					Name:      "github.com/anchore/archiver/v3",
					Version:   "v3.5.2",
					PURL:      "pkg:golang/github.com/anchore/archiver@v3.5.2#v3",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/many-packages/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
				{
					Name:      "github.com/anchore/go-testutils",
					Version:   "v0.0.0-20200624184116-66aa578126db",
					PURL:      "pkg:golang/github.com/anchore/go-testutils@v0.0.0-20200624184116-66aa578126db",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/many-packages/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
				{
					Name:      "github.com/anchore/go-version",
					Version:   "v1.2.2-0.20200701162849-18adb9c92b9b",
					PURL:      "pkg:golang/github.com/anchore/go-version@v1.2.2-0.20200701162849-18adb9c92b9b",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/many-packages/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
				{
					Name:      "github.com/anchore/stereoscope",
					Version:   "v0.0.0-20200706164556-7cf39d7f4639",
					PURL:      "pkg:golang/github.com/anchore/stereoscope@v0.0.0-20200706164556-7cf39d7f4639",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/many-packages/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
				{
					Name:      "github.com/bmatcuk/doublestar",
					Version:   "v8.8.8",
					PURL:      "pkg:golang/github.com/bmatcuk/doublestar@v8.8.8",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/many-packages/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
				{
					Name:      "github.com/go-test/deep",
					Version:   "v1.0.6",
					PURL:      "pkg:golang/github.com/go-test/deep@v1.0.6",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/go-mod-fixtures/many-packages/go.mod")),
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			c := newGoModCataloger(DefaultCatalogerConfig())
			pkgtest.NewCatalogTester().
				FromFile(t, test.fixture).
				Expects(test.expected, nil).
				WithResolver(fileresolver.Empty{}).
				TestParser(t, c.parseGoModFile)
		})
	}
}

func Test_GoSumHashes(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/go-sum-hashes",
			expected: []pkg.Package{
				{
					Name:      "github.com/CycloneDX/cyclonedx-go",
					Version:   "v0.6.0",
					PURL:      "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0",
					Locations: file.NewLocationSet(file.NewLocation("go.mod")),
					FoundBy:   "go-module-file-cataloger",
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata:  pkg.GolangModuleEntry{},
				},
				{
					Name:      "github.com/acarl005/stripansi",
					Version:   "v0.0.0-20180116102854-5a71ef0e047d",
					PURL:      "pkg:golang/github.com/acarl005/stripansi@v0.0.0-20180116102854-5a71ef0e047d",
					Locations: file.NewLocationSet(file.NewLocation("go.mod")),
					FoundBy:   "go-module-file-cataloger",
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata: pkg.GolangModuleEntry{
						H1Digest: "h1:licZJFw2RwpHMqeKTCYkitsPqHNxTmd4SNR5r94FGM8=",
					},
				},
				{
					Name:      "github.com/mgutz/ansi",
					Version:   "v0.0.0-20200706080929-d51e80ef957d",
					PURL:      "pkg:golang/github.com/mgutz/ansi@v0.0.0-20200706080929-d51e80ef957d",
					Locations: file.NewLocationSet(file.NewLocation("go.mod")),
					FoundBy:   "go-module-file-cataloger",
					Language:  pkg.Go,
					Type:      pkg.GoModulePkg,
					Metadata: pkg.GolangModuleEntry{
						H1Digest: "h1:5PJl274Y63IEHC+7izoQE9x6ikvDFZS2mDVS3drnohI=",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expected, nil).
				TestCataloger(t, NewGoModuleFileCataloger(CatalogerConfig{}))
		})
	}
}

func Test_corruptGoMod(t *testing.T) {
	c := NewGoModuleFileCataloger(DefaultCatalogerConfig().WithSearchRemoteLicenses(false))
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/corrupt").
		WithError().
		TestCataloger(t, c)
}

func Test_parseGoSource_packageResolution(t *testing.T) {
	tests := []struct {
		name             string
		fixturePath      string
		config           CatalogerConfig
		expectedPkgs     []string
		expectedRels     []string
		expectedLicenses map[string][]string
	}{
		{
			name:        "go-source with direct, transitive, and deps of transitive",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			expectedPkgs: []string{
				"anchore.io/not/real @  (go.mod)",
				"github.com/davecgh/go-spew @ v1.1.1 (go.mod)",
				"github.com/go-viper/mapstructure/v2 @ v2.2.1 (go.mod)",
				"github.com/google/uuid @ v1.6.0 (go.mod)",
				"github.com/pmezard/go-difflib @ v1.0.0 (go.mod)",
				"github.com/sagikazarmark/locafero @ v0.7.0 (go.mod)",
				"github.com/sirupsen/logrus @ v1.9.3 (go.mod)",
				"github.com/sourcegraph/conc @ v0.3.0 (go.mod)",
				"github.com/spf13/afero @ v1.12.0 (go.mod)",
				"github.com/spf13/cast @ v1.7.1 (go.mod)",
				"github.com/spf13/pflag @ v1.0.6 (go.mod)",
				"github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod)",
				"github.com/subosito/gotenv @ v1.6.0 (go.mod)",
				"go.uber.org/multierr @ v1.10.0 (go.mod)",
				"go.uber.org/zap @ v1.27.0 (go.mod)",
				"golang.org/x/sys @ v0.33.0 (go.mod)",
				"golang.org/x/text @ v0.21.0 (go.mod)",
				"gopkg.in/yaml.v3 @ v3.0.1 (go.mod)",
				"github.com/fsnotify/fsnotify @ v1.8.0 (go.mod)",
				"github.com/pelletier/go-toml/v2 @ v2.2.3 (go.mod)",
				"github.com/frankban/quicktest @ v1.14.6 (go.mod)",
				"github.com/google/go-cmp @ v0.6.0 (go.mod)",
				"github.com/kr/pretty @ v0.3.1 (go.mod)",
				"github.com/kr/text @ v0.2.0 (go.mod)",
				"github.com/rogpeppe/go-internal @ v1.9.0 (go.mod)",
				"go.uber.org/goleak @ v1.3.0 (go.mod)",
				"gopkg.in/check.v1 @ v1.0.0-20190902080502-41f04d3bba15 (go.mod)",
			},
			expectedRels: []string{
				"github.com/davecgh/go-spew @ v1.1.1 (go.mod) [dependency-of] github.com/stretchr/testify @ v1.10.0 (go.mod)",
				"github.com/frankban/quicktest @ v1.14.6 (go.mod) [dependency-of] github.com/spf13/cast @ v1.7.1 (go.mod)",
				"github.com/fsnotify/fsnotify @ v1.8.0 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/go-viper/mapstructure/v2 @ v2.2.1 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/google/go-cmp @ v0.6.0 (go.mod) [dependency-of] github.com/frankban/quicktest @ v1.14.6 (go.mod)",
				"github.com/google/uuid @ v1.6.0 (go.mod) [dependency-of] anchore.io/not/real @  (go.mod)",
				"github.com/kr/pretty @ v0.3.1 (go.mod) [dependency-of] github.com/frankban/quicktest @ v1.14.6 (go.mod)",
				"github.com/kr/pretty @ v0.3.1 (go.mod) [dependency-of] gopkg.in/check.v1 @ v1.0.0-20190902080502-41f04d3bba15 (go.mod)",
				"github.com/kr/text @ v0.2.0 (go.mod) [dependency-of] github.com/kr/pretty @ v0.3.1 (go.mod)",
				"github.com/pelletier/go-toml/v2 @ v2.2.3 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/pmezard/go-difflib @ v1.0.0 (go.mod) [dependency-of] github.com/stretchr/testify @ v1.10.0 (go.mod)",
				"github.com/rogpeppe/go-internal @ v1.9.0 (go.mod) [dependency-of] github.com/kr/pretty @ v0.3.1 (go.mod)",
				"github.com/sagikazarmark/locafero @ v0.7.0 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/sirupsen/logrus @ v1.9.3 (go.mod) [dependency-of] anchore.io/not/real @  (go.mod)",
				"github.com/sourcegraph/conc @ v0.3.0 (go.mod) [dependency-of] github.com/sagikazarmark/locafero @ v0.7.0 (go.mod)",
				"github.com/spf13/afero @ v1.12.0 (go.mod) [dependency-of] github.com/sagikazarmark/locafero @ v0.7.0 (go.mod)",
				"github.com/spf13/afero @ v1.12.0 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/spf13/cast @ v1.7.1 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/spf13/pflag @ v1.0.6 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/spf13/viper @ v1.20.1 (go.mod) [dependency-of] anchore.io/not/real @  (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] anchore.io/not/real @  (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] github.com/pelletier/go-toml/v2 @ v2.2.3 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] github.com/sagikazarmark/locafero @ v0.7.0 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] github.com/sirupsen/logrus @ v1.9.3 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] github.com/sourcegraph/conc @ v0.3.0 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] github.com/subosito/gotenv @ v1.6.0 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] go.uber.org/multierr @ v1.10.0 (go.mod)",
				"github.com/stretchr/testify @ v1.10.0 (go.mod) [dependency-of] go.uber.org/zap @ v1.27.0 (go.mod)",
				"github.com/subosito/gotenv @ v1.6.0 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"go.uber.org/goleak @ v1.3.0 (go.mod) [dependency-of] go.uber.org/zap @ v1.27.0 (go.mod)",
				"go.uber.org/multierr @ v1.10.0 (go.mod) [dependency-of] go.uber.org/zap @ v1.27.0 (go.mod)",
				"go.uber.org/zap @ v1.27.0 (go.mod) [dependency-of] anchore.io/not/real @  (go.mod)",
				"golang.org/x/sys @ v0.33.0 (go.mod) [dependency-of] github.com/fsnotify/fsnotify @ v1.8.0 (go.mod)",
				"golang.org/x/sys @ v0.33.0 (go.mod) [dependency-of] github.com/sirupsen/logrus @ v1.9.3 (go.mod)",
				"golang.org/x/text @ v0.21.0 (go.mod) [dependency-of] github.com/spf13/afero @ v1.12.0 (go.mod)",
				"golang.org/x/text @ v0.21.0 (go.mod) [dependency-of] github.com/subosito/gotenv @ v1.6.0 (go.mod)",
				"gopkg.in/check.v1 @ v1.0.0-20190902080502-41f04d3bba15 (go.mod) [dependency-of] gopkg.in/yaml.v3 @ v3.0.1 (go.mod)",
				"gopkg.in/yaml.v3 @ v3.0.1 (go.mod) [dependency-of] github.com/spf13/viper @ v1.20.1 (go.mod)",
				"gopkg.in/yaml.v3 @ v3.0.1 (go.mod) [dependency-of] github.com/stretchr/testify @ v1.10.0 (go.mod)",
				"gopkg.in/yaml.v3 @ v3.0.1 (go.mod) [dependency-of] go.uber.org/zap @ v1.27.0 (go.mod)",
			},
			expectedLicenses: map[string][]string{
				"github.com/fsnotify/fsnotify":        {"BSD-3-Clause"},
				"github.com/go-viper/mapstructure/v2": {"MIT"},
				"github.com/google/uuid":              {"BSD-3-Clause"},
				"github.com/pelletier/go-toml/v2":     {"MIT"},
				"github.com/sagikazarmark/locafero":   {"MIT"},
				"github.com/sirupsen/logrus":          {"MIT"},
				"github.com/sourcegraph/conc":         {"MIT"},
				"github.com/spf13/afero":              {"Apache-2.0"},
				"github.com/spf13/cast":               {"MIT"},
				"github.com/spf13/pflag":              {"BSD-3-Clause"},
				"github.com/spf13/viper":              {"MIT"},
				"github.com/subosito/gotenv":          {"MIT"},
				"go.uber.org/multierr":                {"MIT"},
				"go.uber.org/zap":                     {"MIT"},
				"golang.org/x/sys":                    {"BSD-3-Clause"},
				"golang.org/x/text":                   {"BSD-3-Clause"},
				"gopkg.in/yaml.v3":                    {"Apache-2.0", "MIT"},
				"github.com/davecgh/go-spew":          {"ISC"},
				"github.com/pmezard/go-difflib":       {"BSD-3-Clause"},
				"github.com/stretchr/testify":         {"MIT"},
				"github.com/frankban/quicktest":       {"MIT"},
				"github.com/google/go-cmp":            {"BSD-3-Clause"},
				"github.com/kr/text":                  {"MIT"},
				"github.com/kr/pretty":                {"MIT"},
				"github.com/rogpeppe/go-internal":     {"BSD-3-Clause"},
				"go.uber.org/goleak":                  {"MIT"},
				"gopkg.in/check.v1":                   {"BSD-2-Clause"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixturePath).
				ExpectsPackageStrings(tt.expectedPkgs).
				ExpectsRelationshipStrings(tt.expectedRels).
				ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
					for _, p := range pkgs {
						if metadata, ok := p.Metadata.(pkg.GolangSourceEntry); ok {
							// Validate that GolangSourceEntry metadata is present but don't assert on specific field values
							// since these might vary across development machines
							require.IsType(t, pkg.GolangSourceEntry{}, metadata, "expected GolangSourceEntry metadata for package %s", p.Name)
							// Verify that the metadata struct is populated (non-zero values indicate go source method was used)
							require.NotEmpty(t, metadata, "GolangSourceEntry metadata should not be empty for package %s", p.Name)
						}
					}
				}).
				ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
					actualLicenses := make(map[string][]string)
					for _, p := range pkgs {
						for _, l := range p.Licenses.ToSlice() {
							if actualLicenses[p.Name] == nil {
								actualLicenses[p.Name] = make([]string, 0)
							}
							actualLicenses[p.Name] = append(actualLicenses[p.Name], l.Value)
						}
					}
					if diff := cmp.Diff(tt.expectedLicenses, actualLicenses); diff != "" {
						t.Errorf("mismatch in licenses (-want +got):\n%s", diff)
					}
				}).
				TestCataloger(t, NewGoModuleFileCataloger(CatalogerConfig{}))
		})
	}
}
