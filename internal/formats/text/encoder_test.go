package text

import (
	"flag"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
)

var updateTextPresenterGoldenFiles = flag.Bool("update-text", false, "update the *.golden files for text presenters")

func TestTextDirectoryPresenter(t *testing.T) {
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		Format().Presenter(testutils.DirectoryInput(t)),
		*updateTextPresenterGoldenFiles,
	)
}

func TestTextImagePresenter(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		Format().Presenter(testutils.ImageInput(t, testImage, testutils.FromSnapshot())),
		testImage,
		*updateTextPresenterGoldenFiles,
	)
}
