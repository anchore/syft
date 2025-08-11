package golang

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strconv"
	"testing"

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
	// tmp module setup
	// Create a non-temp mod cache dir with known permissions
	modCache := filepath.Join(os.TempDir(), "gomodcache-test-"+strconv.Itoa(os.Getpid()))
	err := os.MkdirAll(modCache, 0o755)
	require.NoError(t, err)
	t.Setenv("GOMODCACHE", modCache)
	t.Cleanup(func() {
		_ = os.RemoveAll(modCache) // swallow error; log if needed
	})
	tests := []struct {
		name         string
		fixturePath  string
		config       CatalogerConfig
		expectedPkgs []pkg.Package
	}{
		{
			name:        "go-source with direct, transitive, and deps of transitive; application scope: './...'",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			expectedPkgs: []pkg.Package{
				//"anchore.io/not/real",
				//"github.com/google/uuid",     // import bin1
				//"github.com/sirupsen/logrus", // module import with transitive
				//"golang.org/x/sys",           // transitive 2 from logrus
				//"go.uber.org/zap",            // direct import bin2
				//"go.uber.org/multierr",       // trans import zap
				//"github.com/spf13/viper",     // everything below this is from `github.com/spf13/viper`
				//"github.com/fsnotify/fsnotify",
				//"github.com/go-viper/mapstructure/v2",
				//"github.com/pelletier/go-toml/v2",
				//"github.com/sagikazarmark/locafero",
				//"github.com/sourcegraph/conc",
				//"github.com/spf13/afero",
				//"github.com/spf13/cast",
				//"github.com/spf13/pflag",
				//"github.com/subosito/gotenv",
				//"golang.org/x/text",
				//"gopkg.in/yaml.v3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixturePath).
				Expects(tt.expectedPkgs, nil).
				TestCataloger(t, NewGoModuleFileCataloger(CatalogerConfig{}))
		})
	}
}

//func Test_parseGoSource_licenses(t *testing.T) {
//	// license scanner setup
//	ctx := context.Background()
//	scanner, _ := licenses.ContextLicenseScanner(ctx)
//	ctx = licenses.SetContextLicenseScanner(ctx, scanner)
//
//	// tmp module setup
//	// Create a non-temp mod cache dir with known permissions
//	modCache := filepath.Join(os.TempDir(), "gomodcache-test-"+strconv.Itoa(os.Getpid()))
//	err := os.MkdirAll(modCache, 0o755)
//	require.NoError(t, err)
//	t.Setenv("GOMODCACHE", modCache)
//	t.Cleanup(func() {
//		_ = os.RemoveAll(modCache) // swallow error; log if needed
//	})
//
//	expectedLicenses := map[string][]string{
//		"github.com/fsnotify/fsnotify":        {"BSD-3-Clause"},
//		"github.com/go-viper/mapstructure/v2": {"MIT"},
//		"github.com/google/uuid":              {"BSD-3-Clause"},
//		"github.com/pelletier/go-toml/v2":     {"MIT"},
//		"github.com/sagikazarmark/locafero":   {"MIT"},
//		"github.com/sirupsen/logrus":          {"MIT"},
//		"github.com/sourcegraph/conc":         {"MIT"},
//		"github.com/spf13/afero":              {"Apache-2.0"},
//		"github.com/spf13/cast":               {"MIT"},
//		"github.com/spf13/pflag":              {"BSD-3-Clause"},
//		"github.com/spf13/viper":              {"MIT"},
//		"github.com/subosito/gotenv":          {"MIT"},
//		"go.uber.org/multierr":                {"MIT"},
//		"go.uber.org/zap":                     {"MIT"},
//		"golang.org/x/sys":                    {"BSD-3-Clause"},
//		"golang.org/x/text":                   {"BSD-3-Clause"},
//		"gopkg.in/yaml.v3":                    {"Apache-2.0", "MIT"},
//	}
//
//	fixturePath := filepath.Join("test-fixtures", "go-source")
//	pkgs, _, err := c.parseGoSourceEntry(ctx)
//	if err != nil {
//		t.Fatalf("parseGoSource returned an error: %v", err)
//	}
//
//	if len(pkgs) == 0 {
//		t.Errorf("expected some modules, got 0")
//	}
//
//	actualLicenses := make(map[string][]string)
//	for _, pkg := range pkgs {
//		for _, l := range pkg.Licenses.ToSlice() {
//			if actualLicenses[pkg.Name] == nil {
//				actualLicenses[pkg.Name] = make([]string, 0)
//			}
//			actualLicenses[pkg.Name] = append(actualLicenses[pkg.Name], l.Value)
//		}
//	}
//	if diff := cmp.Diff(expectedLicenses, actualLicenses); diff != "" {
//		t.Errorf("mismatch in licenses (-want +got):\n%s", diff)
//	}
//}
//
//func Test_parseGoSource_relationships(t *testing.T) {
//	ctx := context.Background()
//
//	// Create a non-temp mod cache dir with known permissions
//	modCache := filepath.Join(os.TempDir(), "gomodcache-test-"+strconv.Itoa(os.Getpid()))
//	err := os.MkdirAll(modCache, 0o755)
//	require.NoError(t, err)
//	t.Setenv("GOMODCACHE", modCache)
//	t.Cleanup(func() {
//		_ = os.RemoveAll(modCache)
//	})
//
//	tests := []struct {
//		name                  string
//		fixturePath           string
//		expectedRelationships map[string][]string
//	}{
//		{
//			name:        "basic go-source relationships",
//			fixturePath: filepath.Join("test-fixtures", "go-source"),
//			expectedRelationships: map[string][]string{
//				"anchore.io/not/real": {
//					"github.com/google/uuid",
//					"github.com/sirupsen/logrus",
//					"github.com/spf13/viper",
//					"go.uber.org/zap",
//				},
//				"github.com/sirupsen/logrus": {"golang.org/x/sys"},
//				"go.uber.org/zap":            {"go.uber.org/multierr"},
//				"github.com/spf13/viper": {
//					"github.com/fsnotify/fsnotify", "github.com/go-viper/mapstructure/v2",
//					"github.com/pelletier/go-toml/v2", "github.com/sagikazarmark/locafero",
//					"github.com/spf13/afero", "github.com/spf13/cast", "github.com/spf13/pflag",
//					"github.com/subosito/gotenv", "gopkg.in/yaml.v3",
//				},
//				"github.com/fsnotify/fsnotify":      {"golang.org/x/sys"},
//				"github.com/spf13/afero":            {"golang.org/x/text"},
//				"github.com/subosito/gotenv":        {"golang.org/x/text"},
//				"github.com/sagikazarmark/locafero": {"github.com/sourcegraph/conc", "github.com/spf13/afero"},
//			},
//		},
//		{
//			name:        "relationships pruned for single entrypoint",
//			fixturePath: filepath.Join("test-fixtures", "go-source"),
//			expectedRelationships: map[string][]string{
//				"anchore.io/not/real": {
//					"github.com/google/uuid",
//					"github.com/sirupsen/logrus",
//					// "go.uber.org/zap",
//					// "github.com/spf13/viper",
//				},
//				"github.com/sirupsen/logrus": {"golang.org/x/sys"},
//				// "go.uber.org/zap":            {"go.uber.org/multierr"},
//				// all  viper dependencies pruned
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		tt := tt
//		t.Run(tt.name, func(t *testing.T) {
//			c := newGoSourceCataloger(tt.config)
//			oldWd, _ := os.Getwd()
//			defer os.Chdir(oldWd)
//
//			if err := os.Chdir(tt.fixturePath); err != nil {
//				t.Fatalf("failed to change dir: %v", err)
//			}
//
//			pkgs, relationships, err := c.parseGoSourceEntry(ctx)
//			if err != nil {
//				t.Fatalf("parseGoSource returned an error: %v", err)
//			}
//
//			if len(pkgs) == 0 {
//				t.Errorf("expected some modules, got 0")
//			}
//
//			actualRelationships := convertRelationships(relationships)
//
//			if diff := cmp.Diff(tt.expectedRelationships, actualRelationships); diff != "" {
//				t.Errorf("mismatch in relationships (-want +got):\n%s", diff)
//			}
//		})
//	}
//}
//
//func convertRelationships(relationships []artifact.Relationship) map[string][]string {
//	actualRelationships := make(map[string][]string)
//	for _, relationship := range relationships {
//		from := relationship.From.(pkg.Package).Name
//		to := relationship.To.(pkg.Package).Name
//		if actualRelationships[to] == nil {
//			actualRelationships[to] = make([]string, 0)
//		}
//		actualRelationships[to] = append(actualRelationships[to], from)
//	}
//	for _, rels := range actualRelationships {
//		sort.Strings(rels)
//	}
//	return actualRelationships
//}
