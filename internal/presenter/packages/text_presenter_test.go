package packages

import (
	"flag"
	"testing"
)

var updateTextPresenterGoldenFiles = flag.Bool("update-text", false, "update the *.golden files for text presenters")

func TestTextDirectoryPresenter(t *testing.T) {
	catalog, metadata, _ := presenterDirectoryInput(t)
	assertPresenterAgainstGoldenSnapshot(t,
		NewTextPresenter(catalog, metadata),
		*updateTextPresenterGoldenFiles,
	)
}

func TestTextImagePresenter(t *testing.T) {
	testImage := "image-simple"
	catalog, metadata, _ := presenterImageInput(t, testImage)
	assertPresenterAgainstGoldenImageSnapshot(t,
		NewTextPresenter(catalog, metadata),
		testImage,
		*updateTextPresenterGoldenFiles,
	)
}
