package helpers

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/rust"
)

func Description(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			return metadata.Description
		case pkg.NpmPackage:
			return metadata.Description
		case rust.RustCargoLockEntry:
			information, err := metadata.GetGeneratedInformation()
			if err != nil {
				return ""
			}
			return information.CargoToml.Package.Description
		}
	}
	return ""
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}
