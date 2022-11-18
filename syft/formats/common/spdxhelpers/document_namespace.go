package spdxhelpers

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/source"
)

const (
	inputImage     = "image"
	inputDirectory = "dir"
	inputFile      = "file"
)

func DocumentNameAndNamespace(srcMetadata source.Metadata) (string, string) {
	name := DocumentName(srcMetadata)
	return name, DocumentNamespace(name, srcMetadata)
}

func DocumentNamespace(name string, srcMetadata source.Metadata) string {
	name = cleanName(name)
	input := "unknown-source-type"
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		input = inputImage
	case source.DirectoryScheme:
		input = inputDirectory
	case source.FileScheme:
		input = inputFile
	}

	uniqueID := uuid.Must(uuid.NewRandom())
	identifier := path.Join(input, uniqueID.String())
	if name != "." {
		identifier = path.Join(input, fmt.Sprintf("%s-%s", name, uniqueID.String()))
	}

	u := url.URL{
		Scheme: "https",
		Host:   "anchore.com",
		Path:   path.Join(internal.ApplicationName, identifier),
	}

	return u.String()
}

// see: https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field
func cleanName(name string) string {
	// remove # according to specification
	name = strings.ReplaceAll(name, "#", "-")
	// remove : for url construction
	name = strings.ReplaceAll(name, ":", "-")
	// clean relative pathing
	return path.Clean(name)
}
