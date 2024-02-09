package internal

import (
	"strings"

	"github.com/anchore/syft/syft/artifact"
)

func ArtifactIDFromDigest(input string) artifact.ID {
	return artifact.ID(strings.TrimPrefix(input, "sha256:"))
}
