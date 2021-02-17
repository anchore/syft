package integration

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func TestCatalogMarksOwningFiles(t *testing.T) {

	// ensure the catalog marks owned packages by file path
	tests := []struct {
		fixture string
	}{
		{
			fixture: "image-owning-package",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", test.fixture)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.fixture)
			defer cleanup()

			_, catalog, _, err := syft.Catalog("docker-archive:"+tarPath, source.SquashedScope)
			if err != nil {
				t.Fatalf("failed to catalog image: %+v", err)
			}

			var owningPkg *pkg.Package
			for p := range catalog.Enumerate(pkg.DebPkg) {
				if p.Name == "python-pil" {
					owningPkg = p
					break
				}
			}
			if owningPkg == nil {
				t.Fatalf("could not find owning package")
			}

			var childPkg *pkg.Package
			for p := range catalog.Enumerate(pkg.PythonPkg) {
				if p.Name == "Pillow" {
					childPkg = p
					break
				}
			}
			if childPkg == nil {
				t.Fatalf("could not find child package")
			}

			if len(childPkg.Relations.ParentsByFileOwnership) != 1 {
				t.Fatalf("unexpected parents: %+v", childPkg.Relations.ParentsByFileOwnership)
			}

			if childPkg.Relations.ParentsByFileOwnership[0] != owningPkg.ID {
				t.Errorf("unexpected parent: %q != %q", childPkg.Relations.ParentsByFileOwnership[0], owningPkg.ID)
			}

		})
	}

}
