package text

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/internal/formats/common/testutils"
	"github.com/anchore/syft/syft/format"
)

var updateTextPresenterGoldenFiles = flag.Bool("update-text", false, "update the *.golden files for text presenters")

func TestTextDirectoryPresenter(t *testing.T) {
	catalog, metadata, d := testutils.DirectoryInput(t)
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, d, source.UnknownScope),
		*updateTextPresenterGoldenFiles,
	)
}

func TestTextImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, d := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		format.NewPresenter(encoder, catalog, &metadata, d, source.SquashedScope),
		testImage,
		*updateTextPresenterGoldenFiles,
	)
}
