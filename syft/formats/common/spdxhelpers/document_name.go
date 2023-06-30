package spdxhelpers

import (
	"github.com/anchore/syft/syft/source"
)

func DocumentName(srcMetadata source.Description) string {
	if srcMetadata.Name != "" {
		return srcMetadata.Name
	}

	switch metadata := srcMetadata.Metadata.(type) {
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
