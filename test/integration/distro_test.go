package integration

import (
	"testing"

	"github.com/anchore/syft/syft/distro"
	"github.com/go-test/deep"
)

func TestDistroImage(t *testing.T) {
	_, _, actualDistro, _ := catalogFixtureImage(t, "image-distro-id")

	expected, err := distro.NewDistro(distro.Busybox, "1.31.1", "")
	if err != nil {
		t.Fatalf("could not create distro: %+v", err)
	}

	for _, d := range deep.Equal(actualDistro, &expected) {
		t.Errorf("found distro difference: %+v", d)
	}

}
