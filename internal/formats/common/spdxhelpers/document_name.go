package spdxhelpers

import (
	"path"
	"strings"

	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

func DocumentName(srcMetadata source.Metadata) string {
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		return cleanSPDXName(srcMetadata.ImageMetadata.UserInput)
	case source.DirectoryScheme:
		return cleanSPDXName(srcMetadata.Path)
	}

	// TODO: is this alright?
	return uuid.Must(uuid.NewRandom()).String()
}

func cleanSPDXName(name string) string {
	// remove # according to specification
	name = strings.ReplaceAll(name, "#", "-")

	// remove : for url construction
	name = strings.ReplaceAll(name, ":", "-")

	// clean relative pathing
	return path.Clean(name)
}
