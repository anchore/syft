package spdxhelpers

import (
	"fmt"
	"path"

	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

const SyftDocumentNamespace = "https://anchore.com/syft"

func DocumentNamespace(name string, srcMetadata source.Metadata) string {
	input := "unknown-source-type"
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		input = "image"
	case source.DirectoryScheme:
		input = "dir"
	}

	uniqueID := uuid.Must(uuid.NewRandom())
	identifier := path.Join(input, uniqueID.String())
	if name != "." {
		identifier = path.Join(input, fmt.Sprintf("%s-%s", name, uniqueID.String()))
	}

	return path.Join(SyftDocumentNamespace, identifier)
}
