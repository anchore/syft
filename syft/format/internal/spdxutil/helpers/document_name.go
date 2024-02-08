package helpers

import (
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directory"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscope"
)

func DocumentName(src source.Description) string {
	if src.Name != "" {
		return src.Name
	}

	switch metadata := src.Metadata.(type) {
	case stereoscope.ImageSourceMetadata:
		return metadata.UserInput
	case directory.Metadata:
		return metadata.Path
	case filesource.Metadata:
		return metadata.Path
	default:
		return "unknown"
	}
}
