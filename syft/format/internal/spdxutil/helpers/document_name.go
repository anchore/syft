package helpers

import (
	"github.com/anchore/syft/syft/source"
)

func DocumentName(src source.Description) string {
	if src.Name != "" {
		return src.Name
	}

	var name string
	switch metadata := src.Metadata.(type) {
	case source.ImageMetadata:
		name = metadata.UserInput
	case source.OCIModelMetadata:
		name = metadata.UserInput
	case source.DirectoryMetadata:
		name = metadata.Path
	case source.FileMetadata:
		name = metadata.Path
	}

	// the SPDX document name is mandatory, and a source read from another SBOM may not have one
	if name == "" {
		return "unknown"
	}
	return name
}
