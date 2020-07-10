// +build integration

package integration

import (
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/go-test/deep"
)

func TestDistroImage(t *testing.T) {
	img, cleanup := testutils.GetFixtureImage(t, "docker-archive", "image-distro-id")
	defer cleanup()

	s, err := imgbom.GetScopeFromImage(img, scope.AllLayersScope)
	if err != nil {
		t.Fatalf("could not populate scope with image: %+v", err)
	}

	actual := imgbom.IdentifyDistro(s)
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
