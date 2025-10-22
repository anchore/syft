package dotnet

import (
	"context"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// binary cataloger will search for .dll and .exe files and create packages based off of the version resources embedded
// as a resource directory within the executable. If there is no evidence of a .NET runtime (a CLR header) then no
// package will be created.
// Deprecated: use depsBinaryCataloger instead which combines the PE and deps.json data which yields more accurate results (will be removed in syft v2.0).
type binaryCataloger struct {
	licenses nugetLicenseResolver
}

func (c binaryCataloger) Name() string {
	return "dotnet-portable-executable-cataloger"
}

func (c binaryCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var unknowns error
	peFiles, ldpeUnknownErr, err := findPEFiles(resolver)
	if err != nil {
		return nil, nil, err
	}
	if ldpeUnknownErr != nil {
		unknowns = unknown.Join(unknowns, ldpeUnknownErr)
	}

	var pkgs []pkg.Package
	for _, pe := range peFiles {
		pkgs = append(pkgs, newDotnetBinaryPackage(pe.VersionResources, pe.Location))
	}

	// Try to resolve *.nupkg License(s)
	for i := range pkgs {
		if licenses, err := c.licenses.getLicenses(ctx, pkgs[i].Name, pkgs[i].Version); err == nil && len(licenses) > 0 {
			pkgs[i].Licenses = pkg.NewLicenseSet(licenses...)
		}
	}

	return pkgs, nil, unknowns
}
