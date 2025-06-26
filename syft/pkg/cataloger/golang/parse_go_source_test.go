package golang

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func Test_parseGoSource_packageResolution(t *testing.T) {
	// go binary cataloger tests should match up with the module detection
	// don't need license scanner setup for this test
	ctx := context.Background()

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
		expectedPkgs []string
	}{
		{
			name:        "go-source with direct, transitive, and deps of transitive; application scope: './...'",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{
				GoSourceConfig: GoSourceConfig{
					ImportPaths: []string{"./..."},
				},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",
				"github.com/google/uuid",     // import bin1
				"github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys",           // transitive 2 from logrus
				"go.uber.org/zap",            // direct import bin2
				"go.uber.org/multierr",       // trans import zap
				"github.com/spf13/viper",     // everything below this is from `github.com/spf13/viper`
				"github.com/fsnotify/fsnotify",
				"github.com/go-viper/mapstructure/v2",
				"github.com/pelletier/go-toml/v2",
				"github.com/sagikazarmark/locafero",
				"github.com/sourcegraph/conc",
				"github.com/spf13/afero",
				"github.com/spf13/cast",
				"github.com/spf13/pflag",
				"github.com/subosito/gotenv",
				"golang.org/x/text",
				"gopkg.in/yaml.v3",
			},
		},
		{
			name:        "go-source with direct and transitive deps; ignored paths; application scope: './...'; do not include ignore deps",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{
				GoSourceConfig: GoSourceConfig{
					IncludeTests:       false,
					IncludeIgnoredDeps: false,
					ImportPaths:        []string{"./..."},
					IgnorePaths:        []string{"github.com/spf13/viper"},
				},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",        // root module
				"github.com/google/uuid",     // import bin1
				"go.uber.org/zap",            // direct import bin2
				"go.uber.org/multierr",       // trans import zap
				"github.com/sirupsen/logrus", // module import with transitive sys
				"golang.org/x/sys",           // transitive 2 from logrus
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
		{
			name:        "go-source with direct and transitive deps; ignored paths; application scope: './...'; include ignore deps",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{
				GoSourceConfig: GoSourceConfig{
					IncludeTests:       false,
					IncludeIgnoredDeps: true,
					ImportPaths:        []string{"./..."},
					IgnorePaths: []string{
						"github.com/sirupsen/logrus",
						"github.com/spf13/viper",
					},
				},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",    // root module
				"github.com/google/uuid", // import bin1
				"go.uber.org/zap",        // direct import bin2
				"go.uber.org/multierr",   // trans import zap
				// "github.com/sirupsen/logrus", // module import with transitive sys
				"golang.org/x/sys", // transitive 2 from logrus; included based on config
				//"github.com/spf13/viper", // everything below this is from `github.com/spf13/viper`
				"github.com/fsnotify/fsnotify",
				"github.com/go-viper/mapstructure/v2",
				"github.com/pelletier/go-toml/v2",
				"github.com/sagikazarmark/locafero",
				"github.com/sourcegraph/conc",
				"github.com/spf13/afero",
				"github.com/spf13/cast",
				"github.com/spf13/pflag",
				"github.com/subosito/gotenv",
				"golang.org/x/text",
				"gopkg.in/yaml.v3",
			},
		},
		{
			name:        "go-source with direct, transitive and test deps; application scope: './...'",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{
				GoSourceConfig: GoSourceConfig{
					IncludeTests: true,
					ImportPaths:  []string{"./..."},
					IgnorePaths:  []string{"github.com/spf13/viper"}, // ignore viper for smaller expectations
				},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",           // root module
				"github.com/google/uuid",        // import bin1
				"go.uber.org/zap",               // direct import bin2
				"go.uber.org/multierr",          // trans import zap
				"github.com/sirupsen/logrus",    // module import with transitive sys
				"golang.org/x/sys",              // transitive 2 from logrus;
				"github.com/pmezard/go-difflib", // tests included
				"github.com/stretchr/testify",
				"github.com/davecgh/go-spew",
				"gopkg.in/yaml.v3",
			},
		},
		{
			name:        "go-source with direct and transitive deps; entrypoint scope: ./cmd/bin1/...",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{
				GoSourceConfig: GoSourceConfig{
					IncludeTests: false,
					ImportPaths:  []string{"./cmd/bin1/..."},
				},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",
				"github.com/google/uuid",     // import bin1
				"github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys",           // transitive 2 from logrus
				// "go.uber.org/zap",         // direct import bin2 <-- not in search path
				// "go.uber.org/multierr",    // trans import zap
				//"github.com/spf13/viper", // part of bin2; everything ignored
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newGoSourceCataloger(tt.config)
			oldWd, _ := os.Getwd()
			defer os.Chdir(oldWd)

			if err := os.Chdir(tt.fixturePath); err != nil {
				t.Fatalf("failed to change dir: %v", err)
			}

			pkgs, _, err := c.parseGoSourceEntry(ctx)
			if err != nil {
				t.Fatalf("parseGoSource returned an error: %v", err)
			}

			if len(pkgs) == 0 {
				t.Errorf("expected some libraries, got 0")
			}

			var actualPkgs []string
			for _, pkg := range pkgs {
				actualPkgs = append(actualPkgs, pkg.Name)
			}

			sort.Strings(tt.expectedPkgs)
			sort.Strings(actualPkgs)

			if diff := cmp.Diff(tt.expectedPkgs, actualPkgs); diff != "" {
				t.Errorf("mismatch in packages (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_parseGoSource_licenses(t *testing.T) {
	// license scanner setup
	ctx := context.Background()
	scanner, _ := licenses.ContextLicenseScanner(ctx)
	ctx = licenses.SetContextLicenseScanner(ctx, scanner)

	// tmp module setup
	// Create a non-temp mod cache dir with known permissions
	modCache := filepath.Join(os.TempDir(), "gomodcache-test-"+strconv.Itoa(os.Getpid()))
	err := os.MkdirAll(modCache, 0o755)
	require.NoError(t, err)
	t.Setenv("GOMODCACHE", modCache)
	t.Cleanup(func() {
		_ = os.RemoveAll(modCache) // swallow error; log if needed
	})

	expectedLicenses := map[string][]string{
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
	}

	fixturePath := filepath.Join("test-fixtures", "go-source")
	config := CatalogerConfig{GoSourceConfig: GoSourceConfig{ImportPaths: []string{"./..."}}}
	c := newGoSourceCataloger(config)
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	if err := os.Chdir(fixturePath); err != nil {
		t.Fatalf("failed to change dir: %v", err)
	}
	pkgs, _, err := c.parseGoSourceEntry(ctx)
	if err != nil {
		t.Fatalf("parseGoSource returned an error: %v", err)
	}

	if len(pkgs) == 0 {
		t.Errorf("expected some modules, got 0")
	}

	actualLicenses := make(map[string][]string)
	for _, pkg := range pkgs {
		for _, l := range pkg.Licenses.ToSlice() {
			if actualLicenses[pkg.Name] == nil {
				actualLicenses[pkg.Name] = make([]string, 0)
			}
			actualLicenses[pkg.Name] = append(actualLicenses[pkg.Name], l.Value)
		}
	}
	if diff := cmp.Diff(expectedLicenses, actualLicenses); diff != "" {
		t.Errorf("mismatch in licenses (-want +got):\n%s", diff)
	}
}

func Test_parseGoSource_relationships(t *testing.T) {
	ctx := context.Background()

	// Create a non-temp mod cache dir with known permissions
	modCache := filepath.Join(os.TempDir(), "gomodcache-test-"+strconv.Itoa(os.Getpid()))
	err := os.MkdirAll(modCache, 0o755)
	require.NoError(t, err)
	t.Setenv("GOMODCACHE", modCache)
	t.Cleanup(func() {
		_ = os.RemoveAll(modCache)
	})

	tests := []struct {
		name                  string
		fixturePath           string
		config                CatalogerConfig
		expectedRelationships map[string][]string
	}{
		{
			name:        "basic go-source relationships",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{
				GoSourceConfig: GoSourceConfig{ImportPaths: []string{"./..."}},
			},
			expectedRelationships: map[string][]string{
				"anchore.io/not/real": {
					"github.com/google/uuid",
					"github.com/sirupsen/logrus",
					"github.com/spf13/viper",
					"go.uber.org/zap",
				},
				"github.com/sirupsen/logrus": {"golang.org/x/sys"},
				"go.uber.org/zap":            {"go.uber.org/multierr"},
				"github.com/spf13/viper": {
					"github.com/fsnotify/fsnotify", "github.com/go-viper/mapstructure/v2",
					"github.com/pelletier/go-toml/v2", "github.com/sagikazarmark/locafero",
					"github.com/spf13/afero", "github.com/spf13/cast", "github.com/spf13/pflag",
					"github.com/subosito/gotenv", "gopkg.in/yaml.v3",
				},
				"github.com/fsnotify/fsnotify":      {"golang.org/x/sys"},
				"github.com/spf13/afero":            {"golang.org/x/text"},
				"github.com/subosito/gotenv":        {"golang.org/x/text"},
				"github.com/sagikazarmark/locafero": {"github.com/sourcegraph/conc", "github.com/spf13/afero"},
			},
		},
		{
			name:        "relationships pruned for single entrypoint",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: CatalogerConfig{GoSourceConfig: GoSourceConfig{
				ImportPaths: []string{"./cmd/bin1/..."}},
			},
			expectedRelationships: map[string][]string{
				"anchore.io/not/real": {
					"github.com/google/uuid",
					"github.com/sirupsen/logrus",
					// "go.uber.org/zap",
					// "github.com/spf13/viper",
				},
				"github.com/sirupsen/logrus": {"golang.org/x/sys"},
				// "go.uber.org/zap":            {"go.uber.org/multierr"},
				// all  viper dependencies pruned
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c := newGoSourceCataloger(tt.config)
			oldWd, _ := os.Getwd()
			defer os.Chdir(oldWd)

			if err := os.Chdir(tt.fixturePath); err != nil {
				t.Fatalf("failed to change dir: %v", err)
			}

			pkgs, relationships, err := c.parseGoSourceEntry(ctx)
			if err != nil {
				t.Fatalf("parseGoSource returned an error: %v", err)
			}

			if len(pkgs) == 0 {
				t.Errorf("expected some modules, got 0")
			}

			actualRelationships := convertRelationships(relationships)

			if diff := cmp.Diff(tt.expectedRelationships, actualRelationships); diff != "" {
				t.Errorf("mismatch in relationships (-want +got):\n%s", diff)
			}
		})
	}
}

func convertRelationships(relationships []artifact.Relationship) map[string][]string {
	actualRelationships := make(map[string][]string)
	for _, relationship := range relationships {
		from := relationship.From.(pkg.Package).Name
		to := relationship.To.(pkg.Package).Name
		if actualRelationships[from] == nil {
			actualRelationships[from] = make([]string, 0)
		}
		actualRelationships[from] = append(actualRelationships[from], to)
	}
	for _, rels := range actualRelationships {
		sort.Strings(rels)
	}
	return actualRelationships
}
