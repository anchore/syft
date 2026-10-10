package javascript

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
)

type licenseSearchCountingResolver struct {
	file.Resolver
	searches int
}

func (r *licenseSearchCountingResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	r.searches++
	return r.Resolver.FilesByGlob(patterns...)
}

func TestPackageJSONLocalLicenses(t *testing.T) {
	scanner, err := licenses.NewDefaultScanner()
	require.NoError(t, err)
	ctx := licenses.SetContextLicenseScanner(context.Background(), scanner)
	for _, enabled := range []bool{true, false} {
		for _, declared := range []bool{true, false} {
			name := "fallback"
			if declared {
				name = "declared"
			}
			if enabled {
				name += "/enabled"
			} else {
				name += "/disabled"
			}
			t.Run(name, func(t *testing.T) {
				resolver := &licenseSearchCountingResolver{Resolver: fileresolver.NewFromUnindexedDirectory("../internal/licenses/testdata")}
				locations, err := resolver.FilesByPath("source.txt")
				require.NoError(t, err)
				require.Len(t, locations, 1)
				body := `{"name":"synthetic-package","version":"1.0.0"}`
				if declared {
					body = `{"name":"synthetic-package","version":"1.0.0","license":"Apache-2.0"}`
				}
				parser := packageJSONParser{cfg: DefaultCatalogerConfig().WithSearchLocalLicenses(enabled)}
				packages, relationships, err := parser.parsePackageJSON(ctx, resolver, nil, file.NewLocationReadCloser(locations[0], io.NopCloser(strings.NewReader(body))))
				require.NoError(t, err)
				require.Empty(t, relationships)
				require.Len(t, packages, 1)
				p := packages[0]
				require.Equal(t, "synthetic-package", p.Name)
				require.Equal(t, "1.0.0", p.Version)
				require.Equal(t, "pkg:npm/synthetic-package@1.0.0", p.PURL)
				require.Equal(t, pkg.NpmPkg, p.Type)
				require.False(t, p.Locations.Empty())
				switch {
				case declared:
					require.Equal(t, 0, resolver.searches)
					require.Equal(t, "Apache-2.0", p.Licenses.ToSlice()[0].Value)
				case enabled:
					require.Equal(t, 1, resolver.searches)
					require.Equal(t, "MIT", p.Licenses.ToSlice()[0].Value)
				default:
					require.Zero(t, resolver.searches)
					require.True(t, p.Licenses.Empty())
				}
			})
		}
	}
}
