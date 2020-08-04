// +build integration

package integration

import (
	"testing"

	"github.com/anchore/syft/syft"

	"github.com/anchore/go-testutils"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/scope"
	"github.com/go-test/deep"
)

func TestDistroImage(t *testing.T) {
	fixtureImageName := "image-distro-id"
	_, cleanup := testutils.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := testutils.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	_, _, actualDistro, err := syft.Catalog("docker-archive://"+tarPath, scope.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}
	if actualDistro == nil {
		t.Fatalf("could not find distro")
	}

	expected, err := distro.NewDistro(distro.Busybox, "1.31.1")
	if err != nil {
		t.Fatalf("could not create distro: %+v", err)
	}

	diffs := deep.Equal(*actualDistro, expected)
	if len(diffs) != 0 {
		for _, d := range diffs {
			t.Errorf("found distro difference: %+v", d)
		}
	}

}
