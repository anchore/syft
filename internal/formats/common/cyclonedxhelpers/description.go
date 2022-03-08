package cyclonedxhelpers

import "github.com/anchore/syft/syft/pkg"

func encodeDescription(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return metadata.Description
		case pkg.NpmPackageJSONMetadata:
			return metadata.Description
		}
	}
	return ""
}

func decodeDescription(description string, metadata interface{}) {
	switch meta := metadata.(type) {
	case *pkg.ApkMetadata:
		meta.Description = description
	case *pkg.NpmPackageJSONMetadata:
		meta.Description = description
	}
}
