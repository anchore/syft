package rust

import (
	"reflect"

	"github.com/anchore/syft/syft/pkg"
)

type CargoMetadata struct {
	Packages []pkg.CargoPackageMetadata `toml:"package"`
}

func init() {
	pkg.MetadataTypeByName[pkg.RustCargoPackageMetadataType] = reflect.TypeOf(CargoMetadata{})
}

// Pkgs returns all of the packages referenced within the Cargo.lock metadata.
func (m CargoMetadata) Pkgs() []*pkg.Package {
	pkgs := make([]*pkg.Package, 0)

	for _, p := range m.Packages {
		if p.Dependencies == nil {
			p.Dependencies = make([]string, 0)
		}
		pkgs = append(pkgs, p.Pkg())
	}

	return pkgs
}
