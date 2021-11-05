package syftjson

import (
	"flag"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
)

var updateJson = flag.Bool("update-json", false, "update the *.golden files for json presenters")

func TestDirectoryPresenter(t *testing.T) {
	testutils.AssertPresenterAgainstGoldenSnapshot(t,
		Format().Presenter(testutils.DirectoryInput(t)),
		*updateJson,
	)
}

func TestImagePresenter(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertPresenterAgainstGoldenImageSnapshot(t,
		Format().Presenter(testutils.ImageInput(t, testImage, testutils.FromSnapshot())),
		testImage,
		*updateJson,
	)
}
