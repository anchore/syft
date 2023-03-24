package nixstore

import (
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Cataloger struct{}

func NewNixStoreCataloger() *Cataloger {
	return &Cataloger{}
}

func (c *Cataloger) Name() string {
	return "nix-store-cataloger"
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	nixStoreFileMatches, err := resolver.FilesByGlob(pkg.NixStoreGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find any nix store directory: %w", err)
	}

	var allPackages []pkg.Package
	pkgMap := make(map[string]interface{})
	for _, storeLocation := range nixStoreFileMatches {
		name, version := extractNameAndVersion(storeLocation.VirtualPath)

		if version != "" {
			nixLookupPkg := pkgMap[fmt.Sprintf("%s-%s", name, version)]
			if nixLookupPkg == nil {
				nixPkg := pkg.NixStoreMetadata{
					Source: name,
					SourceVersion: version,
				}

				p := newNixStorePackage(nixPkg)
				p.Name = name
				p.Version = version
				p.FoundBy = c.Name()
				p.Locations = source.NewLocationSet(storeLocation)
				p.SetID()

				log.Debug(p)

				pkgMap[fmt.Sprintf("%s-%s", name, version)] = p

			} else {
				nixLookupPkg := nixLookupPkg.(pkg.Package)
				nixLookupPkg.Locations = source.NewLocationSet(append(nixLookupPkg.Locations.ToSlice(), storeLocation)...)
				pkgMap[fmt.Sprintf("%s-%s", name, version)] = nixLookupPkg
			}
		}
	}

	for _, p := range pkgMap {
		allPackages = append(allPackages, p.(pkg.Package))
	}
	return allPackages, nil, nil
}
