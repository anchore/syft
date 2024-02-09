package helpers

import (
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

func DocumentName(src source.Description) string {
	if src.Name != "" {
		return src.Name
	}

	switch metadata := src.Metadata.(type) {
	case stereoscopesource.ImageMetadata:
		return metadata.UserInput
	case directorysource.Metadata:
		return metadata.Path
	case filesource.Metadata:
		return metadata.Path
	default:
		return "unknown"
	}
}
