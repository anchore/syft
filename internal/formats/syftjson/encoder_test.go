package syftjson

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/anchore/syft/syft/format"
)

var updateJson = flag.Bool("update-json", false, "update the *.golden files for json presenters")

func TestDirectoryPresenter(t *testing.T) {
	catalog, metadata, distro := testutils.DirectoryInput(t)
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, distro, source.SquashedScope),
		*updateJson,
	)
}

func TestImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, distro := testutils.ImageInput(t, testImage)
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, distro, source.SquashedScope),
		testImage,
		*updateJson,
	)
}
