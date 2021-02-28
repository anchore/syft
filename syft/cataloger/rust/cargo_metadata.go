package rust

import "github.com/anchore/syft/syft/pkg"

type CargoMetadata struct {
	Packages []CargoMetadataPackage `toml:"package"`
}

// Pkgs returns all of the packages referenced within the Cargo.lock metadata.
func (m CargoMetadata) Pkgs() []pkg.Package {
	pkgs := make([]pkg.Package, 0)

	for _, p := range m.Packages {
		pkgs = append(pkgs, p.Pkg())
	}

	return pkgs
}
