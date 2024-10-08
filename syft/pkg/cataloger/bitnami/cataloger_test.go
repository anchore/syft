package bitnami

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitnamiCataloger(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		wantPkgs  []pkg.Package
		wantError require.ErrorAssertionFunc
	}{
		{
			name:    "simple-redis-sbom",
			fixture: "test-fixtures",
			// TODO: add package assertions
		},
		// TODO: add another test case or too, maybe an error case
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
					for i, p := range pkgs {
						assert.Equal(t, p.Name, tt.wantPkgs[i].Name)
						assert.Equal(t, p.Version, tt.wantPkgs[i].Version)
					}
				}).
				TestCataloger(t, NewCataloger())
		})
	}
}
