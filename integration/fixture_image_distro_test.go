// +build integration

package integration

import (
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/go-test/deep"
)

func TestDistroImage(t *testing.T) {
	img, cleanup := testutils.GetFixtureImage(t, "docker-archive", "image-distro-id")
	defer cleanup()

	actual := imgbom.IdentifyDistro(img)
	if actual == nil {
		t.Fatalf("could not find distro")
	}

	expected, err := distro.NewDistro(distro.Busybox, "1.31.1")
	if err != nil {
		t.Fatalf("could not create distro: %+v", err)
	}

	diffs := deep.Equal(*actual, expected)
	if len(diffs) != 0 {
		for _, d := range diffs {
			t.Errorf("found distro difference: %+v", d)
		}
	}

}
