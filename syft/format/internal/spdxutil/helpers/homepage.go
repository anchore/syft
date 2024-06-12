package helpers

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/rust"
)

func Homepage(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.RubyGemspec:
			return metadata.Homepage
		case pkg.NpmPackage:
			return metadata.Homepage
		case rust.RustCargoLockEntry:
			information, err := metadata.GetGeneratedInformation()
			if err != nil {
				return ""
			}
			homepage := information.CargoToml.Package.Homepage
			if homepage == "" {
				homepage = information.CargoToml.Package.Repository
			}
			return homepage
		}
	}
	return ""
}
