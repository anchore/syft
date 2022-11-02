package spdxhelpers

import (
	"fmt"
	"net/url"
	"path"

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
