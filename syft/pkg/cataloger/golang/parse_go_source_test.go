package golang

import (
	"context"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_parseGoSource(t *testing.T) {
	resolver := fileresolver.NewFromUnindexedDirectory(filepath.Join("test-fixtures", "go-source"))
	// go binary cataloger tests should match up with the modules detect
	ctx := context.Background()
	scanner, _ := licenses.ContextLicenseScanner(ctx)
	ctx = licenses.SetContextLicenseScanner(ctx, scanner)
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
			name:        "go-source with direct and transitive deps; tests enabled; application scope: './...'",
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
				"github.com/pmezard/go-difflib", // test
				"github.com/stretchr/testify",   // test
				"github.com/davecgh/go-spew",    // test
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
				// "go.uber.org/zap",            // direct import bin2 <-- not in search path
				// "go.uber.org/multierr",       // trans import zap
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

			pkgs, _, err := c.parseGoSource(ctx, tt.config, resolver)
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
