package golang

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Known bugs:
// no root module detection
func Test_parseGoSource(t *testing.T) {
	ctx := context.Background()
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
				// "anchore.io/not/real",        // root module; ? what do we use as the version here?
				"anchore.io/not/real/cmd",    // entrypoint main.go
				"anchore.io/not/real/pk1",    // localdep 1
				"anchore.io/not/real/pk2",    // localdep 2
				"github.com/google/uuid",     // module import no transitive
				"github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys/unix",      // transitive 2
			},
		},
		{
			name:        "go-source with direct and transitive deps; ignored paths; application scope: './...'",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				includeTests: false,
				importPaths:  []string{"./..."},
				ignoredPaths: []string{"github.com/sirupsen/logrus"},
			},
			expectedPkgs: []string{
				// "anchore.io/not/real",     // root module
				"anchore.io/not/real/cmd", // entrypoint main.go
				"anchore.io/not/real/pk1", // localdep 1
				"anchore.io/not/real/pk2", // localdep 2
				"github.com/google/uuid",  // module import no transitive
				// "github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys/unix", // transitive 2
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
				// "anchore.io/not/real",                   // root module
				"anchore.io/not/real/cmd",               // entrypoint main.go
				"anchore.io/not/real/pk1",               // localdep 1
				"anchore.io/not/real/pk1.test",          // test
				"github.com/pmezard/go-difflib/difflib", // test
				"github.com/stretchr/testify/assert",
				"github.com/davecgh/go-spew/spew", // test
				"gopkg.in/yaml.v3",                // test
				"anchore.io/not/real/pk2",         // localdep 2
				"github.com/google/uuid",          // module import no transitive
				"github.com/sirupsen/logrus",      // module import with transitive
				"golang.org/x/sys/unix",           // transitive 2
			},
		},
		{
			name:        "go-source with direct and transitive deps; entrypoint scope: ./cmd/...",
			fixturePath: filepath.Join("test-fixtures", "go-source"),
			config: goSourceConfig{
				includeTests: false,
				importPaths:  []string{"./cmd/..."},
			},
			expectedPkgs: []string{
				// "anchore.io/not/real",        // root module
				"anchore.io/not/real/cmd",    // entry point
				"anchore.io/not/real/pk1",    // localdep 1
				"anchore.io/not/real/pk2",    // localdep 2
				"github.com/google/uuid",     // module import no transitive
				"github.com/sirupsen/logrus", // module import with transitive
				"golang.org/x/sys/unix",      // transitive 2
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
