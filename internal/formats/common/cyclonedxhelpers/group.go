package cyclonedxhelpers

import "github.com/anchore/syft/syft/pkg"

func Group(p pkg.Package) string {
	if hasMetadata(p) {
		if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok && metadata.PomProperties != nil {
			return metadata.PomProperties.GroupID
		}
	}
	return ""
}
