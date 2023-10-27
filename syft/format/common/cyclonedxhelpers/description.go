package cyclonedxhelpers

import "github.com/anchore/syft/syft/pkg"

func encodeDescription(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			return metadata.Description
		case pkg.NpmPackage:
			return metadata.Description
		}
	}
	return ""
}

func decodeDescription(description string, metadata interface{}) {
	switch meta := metadata.(type) {
	case *pkg.ApkDBEntry:
		meta.Description = description
	case *pkg.NpmPackage:
		meta.Description = description
	}
}
