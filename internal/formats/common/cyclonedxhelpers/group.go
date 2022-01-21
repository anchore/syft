package cyclonedxhelpers

import "github.com/anchore/syft/syft/pkg"

func Group(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.JavaMetadata:
			if metadata.PomProperties != nil {
				return metadata.PomProperties.GroupID
			}
		}
	}
	return ""
}
