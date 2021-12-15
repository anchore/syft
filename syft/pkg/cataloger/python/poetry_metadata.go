package python

import "github.com/anchore/syft/syft/pkg"

type PoetryMetadata struct {
	Packages []PoetryMetadataPackage `toml:"package"`
}

// Pkgs returns all of the packages referenced within the poetry.lock metadata.
func (m PoetryMetadata) Pkgs() []*pkg.Package {
	pkgs := make([]*pkg.Package, 0)

	for _, p := range m.Packages {
		pkgs = append(pkgs, p.Pkg())
	}

	return pkgs
}
