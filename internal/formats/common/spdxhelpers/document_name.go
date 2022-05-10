package spdxhelpers

import (
	"path"
	"strings"

	"github.com/anchore/syft/syft/source"
)

func DocumentName(srcMetadata source.Metadata) string {
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		return cleanName(srcMetadata.ImageMetadata.UserInput)
	case source.DirectoryScheme, source.FileScheme:
		return cleanName(srcMetadata.Path)
	default:
		return "unknown"
	}
}

func cleanName(name string) string {
	// remove # according to specification
	name = strings.ReplaceAll(name, "#", "-")

	// remove : for url construction
	name = strings.ReplaceAll(name, ":", "-")

	// clean relative pathing
	return path.Clean(name)
}
