package helpers

import (
	"github.com/anchore/syft/syft/source"
)

func DocumentName(src source.Description) string {
	if src.Name != "" {
		return src.Name
	}

	switch metadata := src.Metadata.(type) {
	case source.ImageMetadata:
		return metadata.UserInput
	case source.DirectoryMetadata:
		return metadata.Path
	case source.FileMetadata:
		return metadata.Path
	default:
		return "unknown"
	}
}
