package packages

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var updateJSONGoldenFiles = flag.Bool("update-json", false, "update the *.golden files for json presenters")

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestJSONDirectoryPresenter(t *testing.T) {
	catalog, metadata, dist := presenterDirectoryInput(t)
	assertPresenterAgainstGoldenSnapshot(t,
		NewJSONPresenter(catalog, metadata, dist, source.SquashedScope),
		*updateJSONGoldenFiles,
	)

}

func TestJSONImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, dist := presenterImageInput(t, testImage)
	assertPresenterAgainstGoldenImageSnapshot(t,
		NewJSONPresenter(catalog, metadata, dist, source.SquashedScope),
		testImage,
		*updateJSONGoldenFiles,
	)
}
