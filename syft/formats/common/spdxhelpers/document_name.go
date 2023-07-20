package spdxhelpers

import (
	"fmt"

	"github.com/anchore/syft/syft/source"
)

func DocumentName(srcMetadata source.Description) string {
	if srcMetadata.Name != "" {
		return fmt.Sprintf("%s-%s", srcMetadata.Name, srcMetadata.Version)
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
