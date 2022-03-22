package spdxhelpers

import (
	"fmt"
	"path"
	"strings"

	"github.com/anchore/syft/syft/source"
)

func DocumentName(srcMetadata source.Metadata) (string, error) {
	switch srcMetadata.Scheme {
	case source.ImageType:
		return cleanName(srcMetadata.ImageMetadata.UserInput), nil
	case source.DirectoryType, source.FileType:
		return cleanName(srcMetadata.Path), nil
	}

	return "", fmt.Errorf("unable to determine document name from scheme=%q", srcMetadata.Scheme)
}

func cleanName(name string) string {
	// remove # according to specification
	name = strings.ReplaceAll(name, "#", "-")

	// remove : for url construction
	name = strings.ReplaceAll(name, ":", "-")

	// clean relative pathing
	return path.Clean(name)
}
