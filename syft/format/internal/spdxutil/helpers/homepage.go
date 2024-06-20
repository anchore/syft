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
			if sourceInfo := metadata.SourceGeneratedDepInfo; sourceInfo != nil {
				homepage := sourceInfo.CargoToml.Package.Homepage
				if homepage == "" {
					homepage = sourceInfo.CargoToml.Package.Repository
				}
				return homepage
			}
		}
	}
	return ""
}
