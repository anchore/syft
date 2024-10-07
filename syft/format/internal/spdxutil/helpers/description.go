package helpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func Description(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			return metadata.Description
		case pkg.NpmPackage:
			return metadata.Description
		case pkg.RustCargo:
			if cargoEntry := metadata.CargoEntry; cargoEntry != nil {
				return cargoEntry.Description
			}
		}
	}
	return ""
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}
