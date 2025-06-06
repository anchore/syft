package helpers

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	InputImage     = "image"
	InputDirectory = "dir"
	InputFile      = "file"
	InputSnap      = "snap"
)

func DocumentNameAndNamespace(src source.Description, desc sbom.Descriptor) (string, string) {
	name := DocumentName(src)
	return name, DocumentNamespace(name, src, desc)
}

func DocumentNamespace(name string, src source.Description, desc sbom.Descriptor) string {
	name = cleanName(name)
	input := "unknown-source-type"
	switch src.Metadata.(type) {
	case source.ImageMetadata:
		input = InputImage
	case source.DirectoryMetadata:
		input = InputDirectory
	case source.FileMetadata:
		input = InputFile
	case source.SnapMetadata:
		input = InputSnap
	}

	uniqueID := uuid.Must(uuid.NewRandom())
	identifier := path.Join(input, uniqueID.String())
	if name != "." {
		identifier = path.Join(input, fmt.Sprintf("%s-%s", name, uniqueID.String()))
	}

	u := url.URL{
		Scheme: "https",
		Host:   "anchore.com",
		Path:   path.Join(desc.Name, identifier),
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
