package helpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func Homepage(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.RubyGemspec:
			return metadata.Homepage
		case pkg.NpmPackage:
			return metadata.Homepage
		case pkg.RustCargo:
			if cargoEntry := metadata.CargoEntry; cargoEntry != nil {
				if cargoEntry.Homepage != "" {
					return cargoEntry.Homepage
				}
				return cargoEntry.Repository
			}
		}
	}
	return ""
}
