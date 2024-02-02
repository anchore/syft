package helpers

import "github.com/anchore/syft/syft/pkg"

func encodeGroup(p pkg.Package) string {
	if hasMetadata(p) {
		if metadata, ok := p.Metadata.(pkg.JavaArchive); ok && metadata.PomProperties != nil {
			return metadata.PomProperties.GroupID
		}
	}
	return ""
}

func decodeGroup(group string, metadata interface{}) {
	if meta, ok := metadata.(*pkg.JavaArchive); ok {
		if meta.PomProperties == nil {
			meta.PomProperties = &pkg.JavaPomProperties{}
		}
		meta.PomProperties.GroupID = group
	}
}
