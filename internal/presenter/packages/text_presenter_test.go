package packages

import (
	"flag"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
)

var updateTextPresenterGoldenFiles = flag.Bool("update-text", false, "update the *.golden files for text presenters")

func TestTextDirectoryPresenter(t *testing.T) {
	catalog, metadata, _ := testutils.DirectoryInput(t)
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		NewTextPresenter(catalog, metadata),
		*updateTextPresenterGoldenFiles,
	)
}

func TestTextImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, _ := testutils.ImageInput(t, testImage)
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		NewTextPresenter(catalog, metadata),
		testImage,
		*updateTextPresenterGoldenFiles,
	)
}
