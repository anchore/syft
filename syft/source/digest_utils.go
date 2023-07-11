package source

import (
	"strings"

	"github.com/anchore/syft/syft/artifact"
)

func artifactIDFromDigest(input string) artifact.ID {
	return artifact.ID(strings.TrimPrefix(input, "sha256:"))
}
