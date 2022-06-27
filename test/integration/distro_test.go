package integration

import (
	"github.com/anchore/syft/syft/source"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/linux"
)

func TestDistroImage(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-distro-id", source.SquashedScope)

	expected := &linux.Release{
		PrettyName: "BusyBox v1.31.1",
		Name:       "busybox",
		ID:         "busybox",
		IDLike:     []string{"busybox"},
		Version:    "1.31.1",
		VersionID:  "1.31.1",
	}

	assert.Equal(t, expected, sbom.Artifacts.LinuxDistribution)
}
