package helpers

import (
	"github.com/anchore/syft/syft/source"
)

func DocumentName(src source.Description) string {
	if src.Name != "" {
		return src.Name
	}

	switch metadata := src.Metadata.(type) {
	case source.StereoscopeImageSourceMetadata:
		return metadata.UserInput
	case source.DirectorySourceMetadata:
		return metadata.Path
	case source.FileSourceMetadata:
		return metadata.Path
	default:
		return "unknown"
	}
}
