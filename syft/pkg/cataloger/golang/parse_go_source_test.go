package golang

import (
	"context"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/internal/licenses"
)

// Todo: add github.com/spf13/viper for multi level trans example
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
		config       goSourceConfig
		expectedPkgs []string
	}{
		{
			name:        "go-source with direct and transitive deps; application scope: './...'",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				importPaths: []string{"./..."},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",
				"github.com/google/uuid",     // import bin1
				"github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys",           // transitive 2 from logrus
				"go.uber.org/zap",            // direct import bin2
				"go.uber.org/multierr",       // trans import zap
			},
		},
		{
			name:        "go-source with direct and transitive deps; ignored paths; application scope: './...'; do not include ignore deps",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				includeTests:      false,
				includeIgnoreDeps: false,
				importPaths:       []string{"./..."},
				ignorePaths:       []string{"github.com/sirupsen/logrus"},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",    // root module
				"github.com/google/uuid", // import bin1
				"go.uber.org/zap",        // direct import bin2
				"go.uber.org/multierr",   // trans import zap
				// "github.com/sirupsen/logrus", // module import with transitive sys
				// "golang.org/x/sys",       // transitive 2 from logrus
			},
		},
		{
			name:        "go-source with direct and transitive deps; ignored paths; application scope: './...'; include ignore deps",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				includeTests:      false,
				includeIgnoreDeps: true,
				importPaths:       []string{"./..."},
				ignorePaths:       []string{"github.com/sirupsen/logrus"},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",    // root module
				"github.com/google/uuid", // import bin1
				"go.uber.org/zap",        // direct import bin2
				"go.uber.org/multierr",   // trans import zap
				// "github.com/sirupsen/logrus", // module import with transitive sys
				"golang.org/x/sys", // transitive 2 from logrus; included based on config
			},
		},
		{
			name:        "go-source with direct, transitive and test deps; application scope: './...'",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				includeTests: true,
				importPaths:  []string{"./..."},
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
			},
		},
		{
			name:        "go-source with direct and transitive deps; entrypoint scope: ./cmd/bin1/...",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				includeTests: false,
				importPaths:  []string{"./cmd/bin1/..."},
			},
			expectedPkgs: []string{
				"anchore.io/not/real",
				"github.com/google/uuid",     // import bin1
				"github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys",           // transitive 2 from logrus
				// "go.uber.org/zap",         // direct import bin2 <-- not in search path
				// "go.uber.org/multierr",    // trans import zap
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newGoSourceCataloger(CatalogerConfig{})
			oldWd, _ := os.Getwd()
			defer os.Chdir(oldWd)

			if err := os.Chdir(tt.fixturePath); err != nil {
				t.Fatalf("failed to change dir: %v", err)
			}

			pkgs, _, err := c.parseGoSource(ctx, tt.config)
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
		"github.com/google/uuid":     {"BSD-3-Clause"},
		"github.com/sirupsen/logrus": {"MIT"},
		"go.uber.org/multierr":       {"MIT"},
		"go.uber.org/zap":            {"MIT"},
		"golang.org/x/sys":           {"BSD-3-Clause"},
	}

	fixturePath := filepath.Join("test-fixtures", "go-source")
	c := newGoSourceCataloger(CatalogerConfig{})
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	if err := os.Chdir(fixturePath); err != nil {
		t.Fatalf("failed to change dir: %v", err)
	}
	config := goSourceConfig{importPaths: []string{"./..."}}
	pkgs, _, err := c.parseGoSource(ctx, config)
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
	// no licenses needed
	ctx := context.Background()

	//// tmp module setup
	//// Create a non-temp mod cache dir with known permissions
	//modCache := filepath.Join(os.TempDir(), "gomodcache-test-"+strconv.Itoa(os.Getpid()))
	//err := os.MkdirAll(modCache, 0o755)
	//require.NoError(t, err)
	//t.Setenv("GOMODCACHE", modCache)
	//t.Cleanup(func() {
	//	_ = os.RemoveAll(modCache) // swallow error; log if needed
	//})

	fixturePath := filepath.Join("test-fixtures", "go-source")
	c := newGoSourceCataloger(CatalogerConfig{})
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)

	if err := os.Chdir(fixturePath); err != nil {
		t.Fatalf("failed to change dir: %v", err)
	}

	// "anchore.io/not/real", => "github.com/google/uuid",     // import main
	// "anchore.io/not/real", => "github.com/sirupsen/logrus", // import main
	// "anchore.io/not/real", => "go.uber.org/zap",           //  import main
	// "github.com/sirupsen/logrus" => "golang.org/x/sys",     // transitive from logrus
	// "go.uber.org/zap", "go.uber.org/multierr".             //  transitive from zap
	expectedRelationships := map[string][]string{
		"anchore.io/not/real": {
			"github.com/google/uuid",
			"github.com/sirupsen/logrus",
			"go.uber.org/zap",
		},
		"github.com/sirupsen/logrus": {"golang.org/x/sys"},
		"go.uber.org/zap":            {"go.uber.org/multierr"},
	}
	config := goSourceConfig{importPaths: []string{"./..."}}
	pkgs, relationships, err := c.parseGoSource(ctx, config)
	if err != nil {
		t.Fatalf("parseGoSource returned an error: %v", err)
	}

	if len(pkgs) == 0 {
		t.Errorf("expected some modules, got 0")
	}

	actualRelationships := convertRelationships(relationships)

	if diff := cmp.Diff(expectedRelationships, actualRelationships); diff != "" {
		t.Errorf("mismatch in licenses (-want +got):\n%s", diff)
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
	return actualRelationships
}
