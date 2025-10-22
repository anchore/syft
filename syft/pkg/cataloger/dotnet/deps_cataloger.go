package dotnet

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// depsCataloger will search for deps.json file contents.
// Deprecated: use depsBinaryCataloger instead which combines the PE and deps.json data which yields more accurate results (will be removed in syft v2.0).
type depsCataloger struct {
	config   CatalogerConfig
	licenses nugetLicenseResolver
}

func (c depsCataloger) Name() string {
	return "dotnet-deps-cataloger"
}

func (c depsCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	depJSONDocs, unknowns, err := findDepsJSON(resolver)
	if err != nil {
		return nil, nil, err
	}

	pkgs, rels := packagesFromDepsJSON(depJSONDocs, CatalogerConfig{
		DepPackagesMustHaveDLL:  false,
		DepPackagesMustClaimDLL: false,
	})

	// Try to resolve *.nupkg License(s)
	for i := range pkgs {
		if licenses, err := c.licenses.getLicenses(ctx, pkgs[i].Name, pkgs[i].Version); err == nil && len(licenses) > 0 {
			pkgs[i].Licenses = pkg.NewLicenseSet(licenses...)
		}
	}

	return pkgs, rels, unknowns
}
